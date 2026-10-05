# A scaled-out Ferrum relay pool on Oracle Cloud (PRD
# phase-6-anycast-autoscaling.md FR6, relay-mesh.md M3).
#
# Clients reach one public address, the network load balancer, which spreads
# them over the pool. Relays forward to each other through the relay mesh, so
# two peers on different instances still reach each other. Every relay
# heartbeats to the coordinator with the NLB's address (so it's what devices
# are told to use) and its own private mesh address (so the relays learn each
# other). The NLB's health check is the relay's /readyz, so a draining relay
# stops getting new flows.

locals {
  relay_port = 51821
  mesh_port  = 51822
  probe_port = 9101
  nlb_ip     = [for ip in oci_network_load_balancer_network_load_balancer.relay.ip_addresses : ip.ip_address if ip.is_public][0]
}

resource "oci_network_load_balancer_network_load_balancer" "relay" {
  compartment_id = var.compartment_id
  display_name   = "ferrum-relay"
  subnet_id      = var.nlb_subnet_id
  is_private     = false
  # The relays see the client's real address (their per-IP register limits
  # and roaming depend on it), and reply through the NLB.
  is_preserve_source_destination = false
}

resource "oci_network_load_balancer_backend_set" "relay" {
  network_load_balancer_id = oci_network_load_balancer_network_load_balancer.relay.id
  name                     = "ferrum-relay"
  # A client's flows stay on one relay even when its NAT port changes. Any
  # spread would be correct (the mesh forwards between relays); this keeps
  # most traffic to one hop.
  policy             = "TWO_TUPLE"
  is_preserve_source = true

  health_checker {
    protocol           = "HTTP"
    port               = local.probe_port
    url_path           = "/readyz"
    return_code        = 200
    interval_in_millis = 2000
    timeout_in_millis  = 1000
    retries            = 3
  }
}

resource "oci_network_load_balancer_listener" "relay" {
  network_load_balancer_id = oci_network_load_balancer_network_load_balancer.relay.id
  name                     = "ferrum-relay-udp"
  default_backend_set_name = oci_network_load_balancer_backend_set.relay.name
  port                     = local.relay_port
  protocol                 = "UDP"
}

resource "oci_core_instance_configuration" "relay" {
  compartment_id = var.compartment_id
  display_name   = "ferrum-relay"

  instance_details {
    instance_type = "compute"

    launch_details {
      compartment_id = var.compartment_id
      shape          = var.shape

      shape_config {
        ocpus         = var.ocpus
        memory_in_gbs = var.memory_gbs
      }

      source_details {
        source_type = "image"
        image_id    = var.image_id
      }

      create_vnic_details {
        subnet_id        = var.relay_subnet_id
        assign_public_ip = false
        nsg_ids          = [oci_core_network_security_group.relay.id]
      }

      # Instance metadata is readable by anyone who can read this instance
      # configuration, and by any process on the instance. See README.md for
      # keeping the mesh key and token in OCI Vault instead.
      metadata = {
        user_data = base64encode(templatefile("${path.module}/relay-cloud-init.yaml.tftpl", {
          ferrum_url      = var.ferrum_url
          ferrum_sha256   = var.ferrum_sha256
          coordinator_url = var.coordinator_url
          advertise       = "${local.nlb_ip}:${local.relay_port}"
          relay_port      = local.relay_port
          mesh_port       = local.mesh_port
          probe_port      = local.probe_port
          mesh_key        = var.mesh_key
          relay_token     = var.relay_token
        }))
      }
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "oci_core_instance_pool" "relay" {
  compartment_id            = var.compartment_id
  display_name              = "ferrum-relay"
  instance_configuration_id = oci_core_instance_configuration.relay.id
  size                      = var.pool_min

  placement_configurations {
    availability_domain = var.availability_domain
    primary_subnet_id   = var.relay_subnet_id
  }

  load_balancers {
    load_balancer_id = oci_network_load_balancer_network_load_balancer.relay.id
    backend_set_name = oci_network_load_balancer_backend_set.relay.name
    port             = local.relay_port
    vnic_selection   = "PrimaryVnic"
  }

  lifecycle {
    # The autoscaling configuration owns the size after creation.
    ignore_changes = [size]
  }
}

# OCI scales an instance pool natively on CPU or memory only. Relay
# forwarding is CPU-bound, so CPU is the honest native signal; the
# client-count and throughput signals live in Prometheus
# (deploy/observability/prometheus/rules/relay_scaling.yml).
resource "oci_autoscaling_auto_scaling_configuration" "relay" {
  compartment_id       = var.compartment_id
  display_name         = "ferrum-relay"
  cool_down_in_seconds = 300
  is_enabled           = true

  auto_scaling_resources {
    id   = oci_core_instance_pool.relay.id
    type = "instancePool"
  }

  policies {
    display_name = "relay-cpu"
    policy_type  = "threshold"

    capacity {
      initial = var.pool_min
      min     = var.pool_min
      max     = var.pool_max
    }

    rules {
      display_name = "scale-out"
      action {
        type  = "CHANGE_COUNT_BY"
        value = 1
      }
      metric {
        metric_type = "CPU_UTILIZATION"
        threshold {
          operator = "GT"
          value    = var.scale_out_cpu
        }
      }
    }

    rules {
      display_name = "scale-in"
      action {
        type  = "CHANGE_COUNT_BY"
        value = -1
      }
      metric {
        metric_type = "CPU_UTILIZATION"
        threshold {
          operator = "LT"
          value    = var.scale_in_cpu
        }
      }
    }
  }
}
