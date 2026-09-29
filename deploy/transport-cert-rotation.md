# Rotating outer-transport TLS certificates (SEC-007)

QUIC and MASQUE wrap WireGuard in an outer TLS layer. Since SEC-004, every
dialer **pins** the server's key: it accepts a certificate only if the SHA-256
of its public key (SubjectPublicKeyInfo) is on its pin list. A dialer that sees
an unlisted key refuses the connection and logs:

```
<peer or proxy>: server key <hex> matches no configured pin — refusing the connection
```

On the QUIC mesh the dialer also backs off from that peer, so a careless key
change costs more than one handshake. The rule for every roll is the same:

> **Advertise next → roll the server → drop old.**
> Get the new pin onto every dialer's list *before* the server starts using the
> new key, then remove the old pin once nothing presents it.

Dialers accept *any* pin on their list, so while both are listed the roll has
no window in which a connection fails on its pin.

## Where pins come from

| Server | Its TLS key | Who holds the pin list | How "next" is advertised |
|---|---|---|---|
| **Mesh node** (QUIC mesh: every node is a server) | Derived from the node's WireGuard private key, so a WireGuard key rotation *is* a TLS key rotation | The coordinator, per peer, in each network map (`PeerInfo.tls_cert_sha256` + `tls_next_pins`) | The node pre-announces it: `[transport] announce_next_pins` (CLI) or `FerrumClient::set_tls_next_fingerprints` (shells) |
| **MASQUE proxy** / **point-to-point QUIC server** | Whatever the operator configures (third-party proxy: its own cert) | Each client's local `[transport] cert_pins` | Add the next pin to `cert_pins` on every client |

Get a Ferrum node's pin for a given private key with
`ferrum tls-fingerprint --config <a config holding that key>`. For a
third-party proxy:
`openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256`.

## Rolling a mesh node's key

1. **Prepare the next key.** Run `ferrum keygen`, then put the new private key
   in a scratch copy of the node's config and run
   `ferrum tls-fingerprint --config next.toml` to get `NEXT_PIN`. Keep the new
   private key secret, the same as the current one.
2. **Advertise next.** In the node's real config add:
   ```toml
   [transport]
   announce_next_pins = ["NEXT_PIN"]
   ```
   and restart `ferrum up-mesh` (or let its supervised session re-register).
   The coordinator validates the pin (up to 4 next pins; malformed ones are
   refused with `InvalidArgument`) and pushes a fresh map to every connected
   watcher at once. Peers now accept the current pin **or** `NEXT_PIN`.
3. **Wait out propagation.** Connected peers have the new map within
   milliseconds. A peer that is offline gets the full map when it reconnects,
   so there's nothing to wait for on its account.
4. **Roll.** Rotate the node's key at the coordinator, carrying the new pin:
   `FerrumClient::rotate_key_with_pins(coordinator, OLD_PUB, NEW_PUB, NEXT_PIN, [])`
   (or `ControlClient::rotate_key_with_pins`). That atomically moves the
   registration to the new key, keeping its tunnel IP, and makes `NEXT_PIN`
   current. Then switch the node's `private_key` to the new key, remove
   `announce_next_pins`, and restart. A peer that dials before its map update
   lands still has `NEXT_PIN` listed, so it connects instead of failing and
   backing off.
5. **Drop old.** Automatic: a rotation *replaces* the device's whole pin set,
   so the old pin leaves every map with it.

> **Gap:** the `ferrum` CLI has no `rotate-key` command yet, so step 4 goes
> through the client-core API (`FerrumClient` / `ControlClient`) from a shell or
> a small tool. The plain `rotate_key` (no pins) still exists for non-TLS
> transports. On a QUIC node it clears the pin, and peers then dial unpinned,
> with a warning, until the node re-registers.

## Rolling a MASQUE proxy or point-to-point QUIC server

1. **Advertise next.** Add the new certificate's pin to every client's
   `[transport] cert_pins`, keeping the current one:
   ```toml
   cert_pins = ["CURRENT_PIN", "NEXT_PIN"]
   ```
   Clients re-read it on restart.
2. **Roll the server** to the new certificate. Clients reconnect and match
   `NEXT_PIN`.
3. **Drop old.** Remove `CURRENT_PIN` from every client.

These pins are client-local today. Advertising proxy pins from the coordinator
is a follow-up.

## Revoking

- **A compromised mesh-node key:** rotate it immediately (above), which replaces
  its pin set everywhere, or revoke the device in the admin panel, which removes
  it from every map. Don't pre-announce a key you suspect is exposed.
- **A compromised proxy key:** remove its pin from every client's `cert_pins`.
  Clients then refuse it outright.
- **An aborted mesh roll:** remove `announce_next_pins` and re-register. The next
  pin leaves every map.
