//! The gRPC [`Coordinator`] service implementation over the [`Registry`].

use std::sync::{Arc, Mutex};

use tonic::{Request, Response, Status};
use vpn_control_proto::coordinator::coordinator_server::Coordinator;
use vpn_control_proto::coordinator::{
    NetworkMapRequest, NetworkMapResponse, PeerInfo, RegisterDeviceRequest, RegisterDeviceResponse,
};

use crate::registry::Registry;

/// Coordinator gRPC service backed by a shared [`Registry`].
pub struct CoordinatorService {
    registry: Arc<Mutex<Registry>>,
}

impl CoordinatorService {
    /// Build a service over a shared registry.
    pub fn new(registry: Arc<Mutex<Registry>>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl Coordinator for CoordinatorService {
    async fn register_device(
        &self,
        request: Request<RegisterDeviceRequest>,
    ) -> Result<Response<RegisterDeviceResponse>, Status> {
        let req = request.into_inner();
        let mut reg = self.registry.lock().expect("registry mutex poisoned");
        let ip = reg
            .register(&req.public_key, &req.name, &req.endpoint, &req.tags)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Response::new(RegisterDeviceResponse {
            assigned_cidr: format!("{ip}/32"),
        }))
    }

    async fn get_network_map(
        &self,
        request: Request<NetworkMapRequest>,
    ) -> Result<Response<NetworkMapResponse>, Status> {
        let req = request.into_inner();
        let reg = self.registry.lock().expect("registry mutex poisoned");
        let peers = reg
            .network_map(&req.public_key)
            .into_iter()
            .map(|d| PeerInfo {
                public_key: d.public_key,
                endpoint: d.endpoint,
                allowed_ips: vec![format!("{}/32", d.tunnel_ip)],
            })
            .collect();
        Ok(Response::new(NetworkMapResponse { peers }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use vpn_control_proto::coordinator::coordinator_client::CoordinatorClient;
    use vpn_control_proto::coordinator::coordinator_server::CoordinatorServer;

    /// End-to-end over real gRPC on localhost: register two devices, then a
    /// network-map request returns the other peer with its assigned address.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_and_get_map_over_grpc() {
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let svc = CoordinatorService::new(registry);

        // Bind first so the listening socket accepts into its backlog (no race
        // with the client connecting before the server task starts serving).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(CoordinatorServer::new(svc))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let mut client = CoordinatorClient::connect(format!("http://{addr}"))
            .await
            .unwrap();

        let a = client
            .register_device(RegisterDeviceRequest {
                public_key: "AAA".into(),
                name: "a".into(),
                endpoint: "1.1.1.1:51820".into(),
                tags: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(a.assigned_cidr, "10.8.0.2/32");

        let b = client
            .register_device(RegisterDeviceRequest {
                public_key: "BBB".into(),
                name: "b".into(),
                endpoint: "2.2.2.2:51820".into(),
                tags: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(b.assigned_cidr, "10.8.0.3/32");

        let map = client
            .get_network_map(NetworkMapRequest {
                public_key: "AAA".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(map.peers.len(), 1);
        assert_eq!(map.peers[0].public_key, "BBB");
        assert_eq!(map.peers[0].endpoint, "2.2.2.2:51820");
        assert_eq!(map.peers[0].allowed_ips, vec!["10.8.0.3/32".to_string()]);
    }
}
