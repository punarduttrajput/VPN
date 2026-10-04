#![no_main]
//! libFuzzer entry for `ferrum_fuzz::relay_challenge` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::relay_challenge(data));
