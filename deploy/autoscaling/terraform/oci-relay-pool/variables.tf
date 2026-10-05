variable "compartment_id" {
  description = "OCID of the compartment everything goes in."
  type        = string
}

variable "availability_domain" {
  description = "Availability domain for the pool, e.g. \"Uocm:EU-FRANKFURT-1-AD-1\"."
  type        = string
}

variable "vcn_id" {
  description = "OCID of the VCN the relay and NLB subnets are in."
  type        = string
}

variable "vcn_cidr" {
  description = "The VCN's CIDR: the NLB's health checks and Prometheus scrape the relays from inside it."
  type        = string
}

variable "relay_subnet_id" {
  description = "OCID of the private subnet the relay instances go in."
  type        = string
}

variable "nlb_subnet_id" {
  description = "OCID of the public subnet the network load balancer goes in."
  type        = string
}

variable "image_id" {
  description = "OCID of the instance image (any systemd Linux with curl and sha256sum)."
  type        = string
}

variable "shape" {
  description = "Instance shape."
  type        = string
  default     = "VM.Standard.A1.Flex"
}

variable "ocpus" {
  description = "OCPUs per relay (flexible shapes)."
  type        = number
  default     = 1
}

variable "memory_gbs" {
  description = "Memory per relay in GB (flexible shapes)."
  type        = number
  default     = 6
}

variable "pool_min" {
  description = "Fewest relays. Two keeps the pool up through one failure."
  type        = number
  default     = 2

  validation {
    condition     = var.pool_min >= 1
    error_message = "pool_min must be at least 1."
  }
}

variable "pool_max" {
  description = "Most relays."
  type        = number
  default     = 6

  validation {
    condition     = var.pool_max >= var.pool_min
    error_message = "pool_max must be at least pool_min."
  }
}

variable "scale_out_cpu" {
  description = "Add a relay when average CPU is above this percentage."
  type        = number
  default     = 70
}

variable "scale_in_cpu" {
  description = "Remove a relay when average CPU is below this percentage."
  type        = number
  default     = 20
}

variable "ferrum_url" {
  description = "HTTPS URL of the ferrum binary for the image's architecture."
  type        = string

  validation {
    condition     = startswith(var.ferrum_url, "https://")
    error_message = "ferrum_url must be an https:// URL."
  }
}

variable "ferrum_sha256" {
  description = "SHA-256 of that binary; an instance that downloads anything else refuses to run it."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.ferrum_sha256))
    error_message = "ferrum_sha256 must be 64 lowercase hex characters."
  }
}

variable "coordinator_url" {
  description = "The coordinator's gRPC URL, reachable from the relay subnet."
  type        = string
}

variable "relay_token" {
  description = "OIDC bearer token with the relay tag, if the coordinator uses OIDC; empty otherwise."
  type        = string
  default     = ""
  sensitive   = true
}

variable "mesh_key" {
  description = "The relay mesh key: 32 random bytes, base64 (head -c 32 /dev/urandom | base64)."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9+/]{43}=$", var.mesh_key))
    error_message = "mesh_key must be 32 bytes, base64."
  }
}
