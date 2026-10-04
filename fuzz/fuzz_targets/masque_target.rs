#![no_main]
//! libFuzzer entry for `ferrum_fuzz::masque_target` (SEC-017).
libfuzzer_sys::fuzz_target!(|data: &[u8]| ferrum_fuzz::masque_target(data));
