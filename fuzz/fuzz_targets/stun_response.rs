#![no_main]
//! libFuzzer entry for `ferrum_fuzz::stun_response` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::stun_response(data));
