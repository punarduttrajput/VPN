output "relay_address" {
  description = "The address devices use: every relay advertises it to the coordinator."
  value       = "${local.nlb_ip}:${local.relay_port}"
}

output "instance_pool_id" {
  description = "OCID of the relay instance pool."
  value       = oci_core_instance_pool.relay.id
}

output "network_load_balancer_id" {
  description = "OCID of the relay network load balancer."
  value       = oci_network_load_balancer_network_load_balancer.relay.id
}
