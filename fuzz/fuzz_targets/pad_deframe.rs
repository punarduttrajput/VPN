#![no_main]
//! libFuzzer entry for `ferrum_fuzz::pad_deframe` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::pad_deframe(data));
