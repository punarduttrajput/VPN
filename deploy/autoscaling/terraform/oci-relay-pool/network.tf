# What the relays accept: client UDP from anywhere (through the NLB, which
# keeps the source address), mesh UDP only from other relays, and the probe
# port only from inside the VCN (NLB health checks, Prometheus).

resource "oci_core_network_security_group" "relay" {
  compartment_id = var.compartment_id
  vcn_id         = var.vcn_id
  display_name   = "ferrum-relay"
}

resource "oci_core_network_security_group_security_rule" "relay_clients" {
  network_security_group_id = oci_core_network_security_group.relay.id
  description               = "Relay clients"
  direction                 = "INGRESS"
  protocol                  = "17" # UDP
  source_type               = "CIDR_BLOCK"
  source                    = "0.0.0.0/0"

  udp_options {
    destination_port_range {
      min = local.relay_port
      max = local.relay_port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "relay_mesh" {
  network_security_group_id = oci_core_network_security_group.relay.id
  description               = "Relay mesh, between relays only"
  direction                 = "INGRESS"
  protocol                  = "17"
  source_type               = "NETWORK_SECURITY_GROUP"
  source                    = oci_core_network_security_group.relay.id

  udp_options {
    destination_port_range {
      min = local.mesh_port
      max = local.mesh_port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "relay_probes" {
  network_security_group_id = oci_core_network_security_group.relay.id
  description               = "Health checks and metrics, from inside the VCN"
  direction                 = "INGRESS"
  protocol                  = "6" # TCP
  source_type               = "CIDR_BLOCK"
  source                    = var.vcn_cidr

  tcp_options {
    destination_port_range {
      min = local.probe_port
      max = local.probe_port
    }
  }
}

resource "oci_core_network_security_group_security_rule" "relay_egress" {
  network_security_group_id = oci_core_network_security_group.relay.id
  description               = "Replies, the coordinator, the binary download"
  direction                 = "EGRESS"
  protocol                  = "all"
  destination_type          = "CIDR_BLOCK"
  destination               = "0.0.0.0/0"
}
