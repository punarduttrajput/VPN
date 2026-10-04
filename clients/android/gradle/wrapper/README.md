# Gradle wrapper

`gradle-wrapper.jar` is the stock Gradle wrapper bootstrap, committed so
`./gradlew` works without a local Gradle install. It runs on every Android
build, so it's pinned like the other vendored binaries (SEC-008).

## Provenance

| Field | Value |
|-------|-------|
| Source | Gradle 8.9 (`gradle wrapper --gradle-version 8.9`) |
| Official checksum | <https://services.gradle.org/distributions/gradle-8.9-wrapper.jar.sha256> |
| `gradle-wrapper.jar` SHA-256 | `498495120a03b9a6ab5d155f5de3c8f0d986a449153702fb80fc80e134484f17` (matches the official checksum; checked 2026-09-29) |
| Distribution SHA-256 | `d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab` (`gradle-8.9-bin.zip`, from <https://services.gradle.org/distributions/gradle-8.9-bin.zip.sha256>) |

The jar's digest is pinned in [`vendor/SHA256SUMS`](../../../../vendor/SHA256SUMS)
and checked by [`scripts/verify-vendored.sh`](../../../../scripts/verify-vendored.sh)
in CI. The distribution digest is `distributionSha256Sum` in
`gradle-wrapper.properties`, so the wrapper itself refuses a Gradle
download that doesn't match.

## Updating

1. `./gradlew wrapper --gradle-version <X.Y> --gradle-distribution-sha256-sum <sha>`
   (the distribution sha is at
   `https://services.gradle.org/distributions/gradle-<X.Y>-bin.zip.sha256`).
2. Confirm the new jar's SHA-256 matches
   `https://services.gradle.org/distributions/gradle-<X.Y>-wrapper.jar.sha256`.
3. Update `vendor/SHA256SUMS` and the table above.
