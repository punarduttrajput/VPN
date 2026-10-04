#![no_main]
//! libFuzzer entry for `ferrum_fuzz::helper_request` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::helper_request(data));
