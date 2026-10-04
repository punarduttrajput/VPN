#![no_main]
//! libFuzzer entry for `ferrum_fuzz::pin_parse` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::pin_parse(data));
