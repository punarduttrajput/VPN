# Deploying Ferrum on a single VM (Oracle Cloud Always-Free)

Brings up the coordinator (control plane + admin panel) and the relay (NAT
traversal fallback) on one VM, so a client can point the desktop app or the
Android APK at a real public endpoint and test the full mesh — including
devices on separate networks, which is what the relay is for.

Written for Oracle Cloud's Always-Free Ampere A1 tier, but nothing here is
Oracle-specific except step 1 — any VPS with a public IP and the ability to
open a UDP port works the same way.

## 1. Create the VM

- Oracle Cloud Console → Compute → Instances → Create Instance.
- Shape: **VM.Standard.A1.Flex** — as of the June 2026 free-tier reduction,
  the Always-Free allowance is **2 OCPU / 12 GB RAM total** across all A1
  instances. One instance using the full allowance is plenty for this.
- Image: **Ubuntu 24.04 (ARM/aarch64)** — simplest Docker install path.
- Networking: assign (or reserve) a **public IPv4 address** — you'll need it
  for `RELAY_ADVERTISE` below and for DNS if you use a domain. A *reserved*
  (not ephemeral) IP is also part of the free tier and won't change if the
  instance restarts.
- Note: Oracle's Always-Free instances can be **reclaimed if idle** (very low
  CPU for an extended period is their anti-squatting policy) — if this is
  sitting mostly idle between client test sessions, check Oracle's current
  reclamation policy so the VM doesn't disappear on you unannounced.

## 2. Open the ports — twice

Oracle Cloud firewalls at **two layers**, and both default to blocking
everything but SSH. Miss either one and the symptom is just "nothing
connects," so do both:

**a. The VCN Security List / Network Security Group** (console-level):
add Ingress rules for the instance's subnet:

| Port | Protocol | Purpose |
|---|---|---|
| 80, 443 | TCP | Caddy (admin panel HTTPS + ACME challenge) |
| 443 | UDP | HTTP/3 (optional, Caddy falls back to TCP fine without it) |
| 50051 | TCP | Coordinator gRPC — clients connect here directly |
| 51820 | UDP | dns-node mesh data plane (DNS through the tunnel) |
| 51821 | UDP | Relay — this is the one that matters for NAT traversal |

**b. The OS firewall** — stock Oracle Ubuntu images ship with `iptables`
rules that *also* block these by default, separately from the cloud
firewall above:

```sh
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 443 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 50051 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 51820 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 51821 -j ACCEPT
sudo netfilter-persistent save   # persist across reboots (apt install iptables-persistent if missing)
```

## 3. Install Docker

```sh
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"    # log out/in (or `newgrp docker`) to pick it up
```

## 4. Clone the repo and configure

```sh
git clone <this-repo-url> ferrum && cd ferrum/deploy/oracle-vm
cp .env.example .env
```

Edit `.env`:
- `RELAY_ADVERTISE` — the VM's public IP + `:51821` (**required** — the
  coordinator refuses to start with this blank; that's intentional, not a bug).
- `DOMAIN` — your domain for the admin panel, if you have one pointed at this
  VM's IP (A record). Leave blank to reach the panel over the raw IP instead
  (Caddy self-signs; one browser warning to click through).
- `OIDC_ISSUER` / `OIDC_AUDIENCE` — the defaults are fine to leave as-is; see
  the note in `.env.example` about what these actually mean here.

## 5. Generate the auth key and mint yourself an admin token

This deployment's OIDC auth is **self-issued** — there's no external identity
provider, `scripts/mint-token.py` *is* the issuer (see its docstring, and
`crates/coordinator/src/auth.rs` for what the coordinator actually verifies).

```sh
pip install cryptography
python3 scripts/mint-token.py init
```

This writes `secrets/jwks.json` (public — gets mounted into the coordinator
container) and `secrets/signing-key.pem` (**private** — never commit it, never
share it; consider keeping it only on your own machine rather than the VM
long-term, and just copying `jwks.json` over).

Mint yourself an admin token (matches whatever you put in `.env`):

```sh
python3 scripts/mint-token.py mint --sub yourname --tags admin \
  --issuer https://ferrum.internal --audience ferrum-admin --ttl 86400
```

Save the printed token somewhere you can paste from — the admin panel asks
for it once per browser session (`sessionStorage`, never sent anywhere but
this coordinator). Mint a **device** token the same way for clients that need
one (`--tags dev`, or whatever tag your ACL policy expects).

## 5b. DNS through the tunnel (leak protection)

This deployment also runs an **in-mesh resolver** (PRD
[leak-protection.md](../../PRD/leak-protection.md) M4): a `dns-node` container
joins the mesh as an ordinary device, and a `dnsmasq` container shares its
network namespace — so DNS is answered at the node's coordinator-assigned
tunnel address, reachable only *through* the tunnel. The coordinator
advertises that address to every device (`--dns` / `DNS_ADVERTISE`), and the
clients' leak protection points system DNS at it while connected.

One-time setup — the dns-node authenticates like any device, so mint it a
long-lived token:

```sh
python3 scripts/mint-token.py mint --sub dns-node --tags device \
  --issuer https://ferrum.internal --audience ferrum-admin \
  --ttl 31536000 > secrets/dns-node-token
```

Set `DNS_NODE_ENDPOINT` in `.env` (the VM public IP, port 51820), and leave
`DNS_ADVERTISE=10.8.0.2` — that's the address a fresh registry assigns the
first device. **If your coordinator DB already has devices**, bring the
dns-node up once, read its actual address from
`docker compose logs dns-node | grep "assigned tunnel address"`, put that in
`DNS_ADVERTISE`, and `docker compose up -d` again.

Verify from any connected client: `dig @10.8.0.2 example.com` resolves (and
times out when the tunnel is down — DNS never leaves the mesh).

## 6. Bring it up

```sh
docker compose up -d --build
```

First build compiles the whole workspace natively on the VM — expect it to
take a while (tens of minutes is normal on a small ARM instance; this mirrors
what a from-scratch `cargo build --release` looks like anywhere). Subsequent
builds after a `git pull` are incremental and much faster.

```sh
docker compose logs -f coordinator   # watch it come up
```

## 7. Test it

- **Admin panel**: open `https://<your-domain-or-ip>` in a browser, paste the
  admin token you minted. You should see the (empty) device list and the ACL
  policy panel — the exact same panel we verified live earlier in this repo's
  own dev loop.
- **Coordinator reachability** from your own machine:
  ```sh
  ferrum up-mesh --coordinator http://<vm-public-ip>:50051 \
    --config <your-config.toml> --endpoint <your-ip>:51820 \
    --token-file <file-holding-a-device-token>
  ```
  A successful "registered; coordinator assigned tunnel address" confirms
  port 50051 is actually reachable end-to-end.

## 8. Point the clients at it

- **Desktop app**: the identity/connect screen's coordinator field →
  `http://<vm-public-ip>:50051` (or your domain, if you also point DNS at it —
  gRPC itself isn't behind Caddy in this setup, only the admin panel is).
- **Android app**: same coordinator address in its connect screen.

## Updating

```sh
git pull
docker compose up -d --build
```

## Hardening beyond a client test

This setup is deliberately minimal for "let a client test it," not a
production baseline. If this needs to run longer-term: put the gRPC channel
behind mTLS too (the coordinator already supports `--tls-cert/--tls-key/--tls-ca` —
see the main `README.md`), rotate the signing key, and consider not keeping
`secrets/signing-key.pem` on the VM at all (mint tokens from your own machine,
copy only `jwks.json` over).

This VM holds the coordinator database and runs the relay, the two components
that see the most metadata. Read the [threat model](../../docs/security/threat-model.md)
(§3 coordinator, §4 relay) for what they can observe, and work through the
operator checklist in [SECURITY.md](../../SECURITY.md) before real users join.

## Also want metrics/dashboards?

`../observability/docker-compose.yml` already expects the coordinator/relay
metrics ports this setup uses (9095/9096) — see its own README to add
Prometheus/Grafana/Jaeger alongside this on the same VM.
