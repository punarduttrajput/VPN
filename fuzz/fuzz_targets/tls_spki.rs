#![no_main]
//! libFuzzer entry for `ferrum_fuzz::tls_spki` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::tls_spki(data));
