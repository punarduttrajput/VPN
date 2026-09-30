//! A minimal HTTP/1 server for operational probes (`/metrics`, `/healthz`,
//! `/readyz`), shared by the coordinator and the relay (SEC-018).
//!
//! Deliberately tiny, so neither binary needs an HTTP-server dependency just to
//! answer a scraper. Unlike the ad-hoc servers it replaced, it:
//! - matches routes **exactly** on a parsed request line (`GET /metricsX` is a
//!   404, not the metrics page);
//! - answers non-`GET` methods with 405;
//! - gives each connection [`REQUEST_TIMEOUT`] to send its request line, so a
//!   client that connects and says nothing (slowloris) can't hold a task open;
//! - serves at most [`MAX_CONNECTIONS`] at once, dropping extras.
//!
//! Probe bodies are the caller's; the coordinator and relay only return
//! constant strings and aggregate metrics (NFR5).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// How long a client has to send its request line.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections served concurrently; more are closed immediately.
pub const MAX_CONNECTIONS: usize = 64;
/// Largest request head read (a probe request is a few dozen bytes).
const MAX_REQUEST: usize = 1024;

/// What a route handler returns: a full response, or `None` for a 404.
pub type Handler = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The request target of an HTTP/1 `GET` request line, without any query
/// string, if `head` starts with a complete, well-formed one. `Err(())` means
/// a well-formed request line with a method other than `GET`.
pub fn get_path(head: &[u8]) -> Option<Result<&str, ()>> {
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    if method != "GET" {
        return Some(Err(()));
    }
    let path = target.split_once('?').map_or(target, |(p, _)| p);
    Some(Ok(path))
}

/// A `200 OK` (or other `status`) response with `content_type` and `body`.
pub fn response(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A `text/plain` response, for the health probes.
pub fn plain(status: &str, body: &str) -> String {
    response(status, "text/plain; charset=utf-8", body)
}

/// The Prometheus exposition response for a rendered metrics body.
pub fn prometheus(body: &str) -> String {
    response("200 OK", "text/plain; version=0.0.4; charset=utf-8", body)
}

fn empty(status: &str) -> String {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

/// Accept connections on `listener` forever, answering each with
/// `handler(path)` (or 404/405/400).
pub async fn serve(listener: TcpListener, handler: Handler) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::debug!("probe endpoint at connection cap; dropping a connection");
            continue;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut head = Vec::with_capacity(128);
            let read = tokio::time::timeout(REQUEST_TIMEOUT, async {
                let mut chunk = [0u8; 256];
                while head.len() < MAX_REQUEST && !head.windows(2).any(|w| w == b"\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
            })
            .await;
            if read.is_err() {
                return; // timed out: just close
            }
            let resp = match get_path(&head) {
                Some(Ok(path)) => handler(path).unwrap_or_else(|| empty("404 Not Found")),
                Some(Err(())) => empty("405 Method Not Allowed"),
                None => empty("400 Bad Request"),
            };
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Bind `addr` and [`serve`] it; logs and returns if the bind fails.
pub async fn bind_and_serve(addr: SocketAddr, handler: Handler) {
    match TcpListener::bind(addr).await {
        Ok(listener) => serve(listener, handler).await,
        Err(e) => tracing::error!(%addr, error = %e, "failed to bind probe endpoint"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_match_exactly_and_ignore_the_query() {
        assert_eq!(
            get_path(b"GET /metrics HTTP/1.1\r\n\r\n"),
            Some(Ok("/metrics"))
        );
        assert_eq!(
            get_path(b"GET /readyz?probe=1 HTTP/1.0\r\n"),
            Some(Ok("/readyz"))
        );
        // A longer path is its own route, not a prefix match.
        assert_eq!(
            get_path(b"GET /metricsX HTTP/1.1\r\n"),
            Some(Ok("/metricsX"))
        );
        assert_eq!(get_path(b"POST /metrics HTTP/1.1\r\n"), Some(Err(())));
    }

    #[test]
    fn malformed_request_lines_are_rejected() {
        for bad in [
            &b""[..],
            b"GET /metrics HTTP/1.1",          // no CRLF yet
            b"GET /metrics\r\n",               // no version
            b"GET metrics HTTP/1.1\r\n",       // not an origin-form target
            b"GET /a /b HTTP/1.1\r\n",         // too many parts
            b"GET /metrics HTTP/2.0\r\n",      // not HTTP/1
            b"\xff\xfe /metrics HTTP/1.1\r\n", // not UTF-8
        ] {
            assert_eq!(get_path(bad), None, "{bad:?}");
        }
    }

    async fn request(addr: SocketAddr, req: &[u8]) -> String {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn serves_routes_and_refuses_everything_else() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler: Handler = Arc::new(|path| match path {
            "/healthz" => Some(plain("200 OK", "ok")),
            _ => None,
        });
        tokio::spawn(serve(listener, handler));

        let ok = request(addr, b"GET /healthz HTTP/1.1\r\n\r\n").await;
        assert!(
            ok.starts_with("HTTP/1.1 200 OK") && ok.ends_with("ok"),
            "{ok}"
        );
        let prefix = request(addr, b"GET /healthzX HTTP/1.1\r\n\r\n").await;
        assert!(prefix.starts_with("HTTP/1.1 404"), "{prefix}");
        let post = request(addr, b"POST /healthz HTTP/1.1\r\n\r\n").await;
        assert!(post.starts_with("HTTP/1.1 405"), "{post}");
        let junk = request(addr, b"hello\r\n").await;
        assert!(junk.starts_with("HTTP/1.1 400"), "{junk}");
    }

    /// A client that connects and sends nothing is dropped after the timeout
    /// rather than holding its task forever.
    #[tokio::test(start_paused = true)]
    async fn silent_clients_are_dropped_after_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(|_| None)));
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(REQUEST_TIMEOUT * 2, s.read(&mut buf))
            .await
            .expect("server must close a silent connection")
            .unwrap_or(0);
        assert_eq!(n, 0, "closed without a response");
    }
}
