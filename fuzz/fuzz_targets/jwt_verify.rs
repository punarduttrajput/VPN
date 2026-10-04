#![no_main]
//! libFuzzer entry for `ferrum_fuzz::jwt_verify` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::jwt_verify(data));
