# Anycast relay PoP

Every PoP runs a relay on the same anycast address and announces that
address's prefix over BGP only while its relay is ready. Clients reach the
nearest ready PoP; a draining or dead PoP drops out of routing. This is FR5 of
[PRD/phase-6-anycast-autoscaling.md](../../PRD/phase-6-anycast-autoscaling.md).

> **Mesh the PoPs.** Two peers that land on different PoPs can only relay to
> each other if the PoPs' relays forward to each other. Give every relay the
> same `--mesh-key-file` and a `--mesh-listen` on its own unicast address,
> reachable from the other PoPs; with `--coordinator` they find each other
> through it, or list them with `--mesh-peer`
> ([PRD/relay-mesh.md](../../PRD/relay-mesh.md); commented out in
> [`ferrum-relay.service`](ferrum-relay.service)). Without the mesh, keep only
> one PoP ready at a time (active/standby).

| File | What it is |
|---|---|
| [`bird.conf`](bird.conf) | bird2: the anycast prefixes as static protocols that start **disabled**, exported only to the BGP upstream. |
| [`ferrum-relay.service`](ferrum-relay.service) | The relay, bound to the anycast address, with its probe endpoint on `127.0.0.1:9101`. |
| [`ferrum-anycast-gate.service`](ferrum-anycast-gate.service) | `ferrum anycast-gate`: polls the relay's `/readyz` and runs `birdc enable` / `disable` on those protocols. |

## How the gate decides

| Relay state | Gate | Route |
|---|---|---|
| `/readyz` 200 for 3 probes in a row | `birdc enable` | announced |
| `/readyz` 503 (draining) | `birdc disable` at once | withdrawn within one probe interval (2 s) |
| No answer, timeout or other status, 3 probes in a row | `birdc disable` | withdrawn within about 6 s |
| Gate starts, or exits cleanly | `birdc disable` | withdrawn |
| Gate crashes or is killed | `ExecStopPost` runs `birdc disable` | withdrawn |

The gate re-applies its decision every 30 s even when nothing changed, because
a restarted bird comes back with the route disabled. A failed `birdc` call is
retried on the next probe. Change the timing with `--interval-ms`,
`--timeout-ms`, `--rise` and `--fall`.

A relay drain (`systemctl stop` or `restart ferrum-relay`, or SIGTERM) goes:
readiness fails → the gate withdraws the route → BGP moves clients' traffic to
the next PoP. Meanwhile the relay keeps serving its existing clients for
`--drain-grace` (20 s) and sends them a GoAway. After a GoAway a client
re-registers every second for 30 s instead of every 25 s, so once its traffic
reaches the next PoP, it's registered there within about a second.

## Setting up a PoP

1. Put the anycast address on the loopback (persist it in your network
   config):
   ```sh
   ip addr add 192.0.2.10/32 dev lo
   ip -6 addr add 2001:db8:f00::10/128 dev lo
   ```
2. Install `ferrum` to `/usr/local/bin`, then the two units, and edit the
   addresses in both:
   ```sh
   install -m 644 ferrum-relay.service ferrum-anycast-gate.service /etc/systemd/system/
   ```
3. Edit every `CHANGE` line in `bird.conf`, check it and install it:
   ```sh
   bird -p -c bird.conf && install -m 640 -g bird bird.conf /etc/bird/bird.conf
   systemctl restart bird
   ```
4. Start the relay, then the gate, and check the route:
   ```sh
   systemctl enable --now ferrum-relay ferrum-anycast-gate
   birdc show protocols ferrum_anycast4     # "up" once the relay is ready
   birdc show route export upstream4        # the prefix, when announced
   ```

Things that matter:

- **Bind the relay to the anycast address** (`--listen 192.0.2.10:51821`), not
  `0.0.0.0`. A wildcard UDP socket replies from whatever source address
  routing picks, usually the PoP's unicast one, and clients drop frames that
  don't come from the relay address they sent to.
- **Tell the coordinator about the relays**, one of two ways:
  - **With the mesh** (recommended): give every relay
    `--coordinator <url> --advertise 192.0.2.10:51821 --mesh-listen <its unicast ip>:51822`.
    The coordinator keys each relay by its mesh address, so the PoPs share
    the advertised anycast address without clashing, one PoP's drain doesn't
    withdraw it, and every relay learns its siblings from the coordinator
    (no `--mesh-peer` list to keep up to date).
  - **Without the mesh**: `ferrum-coordinator --relay 192.0.2.10:51821`
    statically, and no `--coordinator`/`--advertise` on the relays. Without
    a mesh address the registry keys relays by client-facing address, so
    PoPs would share one entry and one drain would withdraw it for all.
- **XDP** (`--xdp-iface`) needs the relay to run as root, which
  `DynamicUser=yes` doesn't allow; adjust the relay unit if you use it.

## What's verified

- In-process (`cargo test -p ferrum-cli anycast_gate`): the gate against a real
  relay and its real probe endpoint. It withdraws on start, announces after the
  rise, withdraws within one interval of the drain, withdraws when the relay
  stops answering, retries a failed `birdc`, re-applies every resync, and
  withdraws on exit. The `birdc` reply check and the hysteresis are unit-tested.
- In-process (`cargo test -p ferrum-transport relay`): the faster keepalive
  after a GoAway.
- Not run yet, needs a Linux host: `bird -p` on `bird.conf`, and the gate
  driving a real bird
  ([runbook §8](../../docs/linux-verification-runbook.md#8-anycast-gate-with-a-real-bird-anycast-m4)).
- External, needs a provider and a fleet: real BGP announcement and withdrawal
  convergence, and the parent PRD's NFR2 (< 20 ms RTT for 90% of users).
