# Ferrum — Private Network Overview

_A plain-language product overview. No technical background required._

---

## A private network your devices can trust

Ferrum links your computers, phones, and servers together over a private,
encrypted connection — wherever they physically are — so the data moving
between them can't be read, tracked, or tampered with along the way.

**At a glance:**
- **3** platforms ready today (Windows, Linux, Android)
- **0** personal data logged
- **< 1 second** typical reconnect after a dropped connection
- **24/7** self-healing connection — no manual reconnecting

---

## 1. What it is

Think of it as private roads, built only for you.

Ordinarily, when your devices talk to each other, the data travels across
the open internet — visible, in principle, to every network it passes
through. Ferrum instead builds a direct, encrypted connection between your
devices themselves. Nothing in between can read it, and where possible, the
connection goes straight from one device to the other, rather than funneling
through a single central server.

```
   LAPTOP  ── encrypted, direct ──  PHONE
      \                              /
       \                            /
        `── encrypted, direct ──  SERVER
```

If two devices can't reach each other directly — strict routers, mobile
networks — Ferrum automatically falls back to a relay, then upgrades back to
a direct connection once it can.

---

## 2. Why it matters

Most of what makes a VPN worth trusting isn't the happy path — it's what
happens when a network is hostile, a connection drops, or a device switches
from wifi to cellular mid-task.

- **Nothing to read** — Every byte between your devices is encrypted
  end-to-end. Even the networks carrying it only see sealed traffic, never
  its contents.
- **Fails safe, not open** — If the encrypted connection ever drops, that
  device's internet access pauses automatically rather than quietly falling
  back to sending things unprotected.
- **Reconnects on its own** — Dropped connections rejoin automatically with
  no manual re-pairing — the connection is designed to be always-on, not
  something you babysit.
- **Direct when it can be** — Devices connect to each other directly
  whenever the network allows it — faster and more private than routing
  every byte through one central point.
- **Works on the move** — Switching wifi networks, losing signal, or
  changing location doesn't force a fresh connection — Ferrum follows the
  device.
- **Can blend in** — An optional disguise mode makes Ferrum traffic look
  like ordinary encrypted web browsing, for networks that try to detect and
  block VPNs.

---

## 3. Available today

A native app on each platform, all speaking the same private network
underneath — a device on a laptop and a device on a phone join the exact
same network.

| Platform | Status |
|---|---|
| **Windows** | Desktop app with automatic reconnect and kill-switch protection. |
| **Linux** | Desktop app with automatic reconnect and kill-switch protection. |
| **Android** | Signed app for phones and tablets, credentials stored in the device's secure keystore. |
| **macOS & iOS** | Planned — currently blocked only on getting access to Apple's development hardware, not a design gap. |

---

## 4. Built to be trusted

Trust that doesn't rely on taking our word for it:

- **Encryption** — Built on **WireGuard**, an open, independently reviewed
  encryption design used and audited across the security industry, not a
  proprietary scheme only we've looked at.
- **Foundation** — Written in **Rust**, a language chosen specifically
  because it rules out entire categories of memory-corruption bugs that have
  historically been the root cause of serious flaws in network software.
- **Privacy** — Our own monitoring collects only aggregate health signals —
  is the service up, how busy is it — never who connected, from where, or to
  what. There's nothing to hand over, because nothing personal is kept.
- **Access control** — Every device is identified by its own key, and which
  devices may talk to which is set by an explicit access policy — nothing is
  reachable by default just because it joined the network.

---

## 5. Where things stand

An honest maturity map, not a sales sheet — stated plainly, so there are no
surprises about what's production-ready today versus what's still being
hardened.

| Area | Status |
|---|---|
| Core encrypted tunnel & multi-device network | ✅ Ready |
| Automatic reconnect & kill-switch | ✅ Ready |
| Windows, Linux & Android apps | ✅ Ready |
| Traffic-disguising mode (works today, still being tested against more networks) | 🟡 Field-testing |
| Web dashboard for managing devices & access rules | 🟡 In progress |
| macOS & iOS apps (needs Apple development hardware) | ⚪ Planned |
| High-throughput acceleration for large deployments | ⚪ Planned |

---

## 6. What's next

The next three milestones, in order:

1. **Web dashboard** — A browser-based screen to see every connected
   device, revoke access instantly, and edit who-can-reach-whom rules — no
   restart or config file required.
2. **Apple support** — Native iPhone, iPad, and Mac apps, once development
   hardware is in place — the underlying groundwork is already shared with
   the Android app.
3. **Large-scale performance tier** — Hardware-accelerated packet handling
   for deployments running well beyond everyday usage, aimed at very
   high-traffic server infrastructure.

---

_Ferrum — private networking, engineered like infrastructure._
