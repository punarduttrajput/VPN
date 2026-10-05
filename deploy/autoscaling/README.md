# Autoscaling the relay tier

A pool of relays that grows and shrinks with load, on Oracle Cloud. This is
FR6 of [PRD/phase-6-anycast-autoscaling.md](../../PRD/phase-6-anycast-autoscaling.md)
and M3 of [PRD/relay-mesh.md](../../PRD/relay-mesh.md).

| Piece | Where |
|---|---|
| OCI instance pool, network load balancer, autoscaling, security group | [`terraform/oci-relay-pool/`](terraform/oci-relay-pool/) |
| Scaling signals and alerts (Prometheus) | [`../observability/prometheus/rules/relay_scaling.yml`](../observability/prometheus/rules/relay_scaling.yml) |
| Relays on fixed hosts (anycast PoPs, a standalone relay) | [`../ansible/`](../ansible/) (role `ferrum_relay`) |

## How it fits together

```
devices ──UDP──▶ network load balancer (public IP, health check = /readyz)
                    │  spreads clients over the pool
          ┌─────────┼─────────┐
       relay 1   relay 2   relay 3  ◀── mesh (private IPs, UDP 51822)
          └──── heartbeat ────┘
                    ▼
               coordinator  (advertises the NLB address, lists mesh peers)
```

- Every relay heartbeats to the coordinator with the **NLB's address** (what
  devices are told to use) and its **own private mesh address**. The
  coordinator keys relays by mesh address, so they all share the advertised
  address and each learns the others (relay mesh M2).
- The NLB may put two peers on different relays. The **relay mesh** forwards
  between relays, so they still reach each other.
- **Scale-out:** OCI's autoscaling adds an instance when average CPU is over
  `scale_out_cpu` (70%). It boots, downloads the pinned binary (checked
  against `ferrum_sha256`), joins the mesh through the coordinator, and the
  NLB starts sending it new flows once `/readyz` answers.
- **Scale-in / replace:** a relay that's stopped cleanly drains first: `/readyz`
  fails so the NLB stops sending it new flows, clients get a GoAway, and the
  relay keeps serving for 20 s. Its siblings keep forwarding to it until its
  heartbeats lapse.

OCI scales instance pools natively on CPU or memory only. Relay forwarding is
CPU-bound, so CPU is a fair native signal. The client-count and throughput
signals are Prometheus alerts (`FerrumRelayPoolScaleOut` / `ScaleIn`, plus
`FerrumRelayPoolNoReadyRelay`). Route them to an operator, or to an
Alertmanager webhook that resizes the pool; the webhook isn't included.

## Using the module

1. A VCN with a public subnet for the NLB and a private subnet for the relays
   (with a NAT gateway, so instances can reach the coordinator and download
   the binary).
2. A coordinator **without** a static `--relay` (the relays announce
   themselves), reachable from the relay subnet.
3. A release binary for the image's architecture, served over HTTPS, and its
   SHA-256.
4. `cp terraform.tfvars.example terraform.tfvars`, fill it in, then:
   ```sh
   cd terraform/oci-relay-pool
   terraform init
   terraform apply
   ```
   `relay_address` in the output is what devices are told to use.

**Secrets.** The mesh key (and the relay token, if any) go into the instance
configuration's `user_data`. Anyone who can read the instance configuration
in your tenancy can read them, and so can any process on a relay instance
(through the metadata service). For production, keep them in OCI Vault and
have the instances fetch them with an instance principal at boot (replace
the two `write_files` entries in the cloud-init template). `terraform.tfvars`
and the
state hold them too: [`.gitignore`](terraform/.gitignore) keeps both out of
git.

## What's verified

- In CI (the Deploy templates workflow): `terraform fmt` and `terraform
  validate` against the OCI provider; the cloud-init template renders and
  passes `cloud-init schema`; the Ansible playbook passes `--syntax-check`,
  and its unit renders (with and without the optional settings) and passes
  `systemd-analyze verify`; the anycast `bird.conf` passes `bird -p`.
- In CI (the observability job): the scaling rules pass `promtool check
  rules` and their unit tests (busy pool, a draining relay's clients counting
  against the ready ones, quiet pool down to the floor of two, no ready relay).
- In-process (Rust tests): the relay mesh, coordinator membership and drain
  behaviour the pool relies on.
- **Not verified (needs an OCI tenancy):** `terraform apply`; the NLB passing
  UDP with the client's source address preserved and the replies going back
  through it; health-check-driven drain; scale-out time against the parent
  PRD's 90 s (NFR4; an instance boot plus download is likely 1–3 minutes);
  whether OCI shuts an instance down cleanly on scale-in, so its relay
  drains, or terminates it outright (then its clients move on at their next
  keepalive, within 25 s).
