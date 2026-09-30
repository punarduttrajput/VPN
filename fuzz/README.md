# Fuzz targets (SEC-017)

libFuzzer targets for every parser of untrusted input that the audit plan
([docs/security/audit-plan.md](../docs/security/audit-plan.md)) lists:

| Target | Parser | Input comes from |
|---|---|---|
| `stun_response` | STUN Binding response | any host that can spoof the STUN server |
| `relay_challenge` | relay Challenge frame (client side) | a relay, or anyone spoofing one |
| `pad_deframe` | `PaddedTransport` framing | the network, before WireGuard |
| `tls_spki` | X.509 → SPKI walk used for pinning | a QUIC/MASQUE server's certificate |
| `pin_parse` | pin strings | config, coordinator network map |
| `jwt_verify` | OIDC bearer-token verification | any coordinator client |
| `masque_target` | CONNECT-UDP path template | any MASQUE proxy client |
| `helper_request` | privileged-helper request framing | local helper clients (Unix) |

Each target's body is an ordinary function in `src/lib.rs`, and
`fuzz_targets/*.rs` just hands it to libFuzzer. The crate is standalone (not in
the root workspace), and the transport parsers it reaches are exposed through
`ferrum_transport::fuzzing`, behind that crate's off-by-default `fuzzing`
feature.

## Running

```sh
cargo install cargo-fuzz           # needs a nightly toolchain and Linux/macOS
cd fuzz
cargo fuzz list
cargo fuzz run stun_response -- -max_total_time=60
```

Without libFuzzer (any host, including Windows), smoke-run every target over
the committed corpus plus deterministic pseudo-random input:

```sh
cargo test --manifest-path fuzz/Cargo.toml --no-default-features
```

CI (`.github/workflows/fuzz.yml`) fuzzes each target for 30 s on every push/PR
and 10 min nightly. A crash fails the job and uploads the reproducer from
`fuzz/artifacts/`. To add a target: a function in `src/lib.rs`, a
`fuzz_targets/<name>.rs` wrapper, a `[[bin]]` in `Cargo.toml`, seeds in
`corpus/<name>/`, and a row in the smoke test's `TARGETS`.

**Not covered yet:** the relay *server*'s frame dispatch, which is inline in
its async serve loop. Fuzzing it needs that dispatch pulled out into a pure
function first.
