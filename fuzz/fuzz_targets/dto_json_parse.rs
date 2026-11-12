//! Fuzz target: roscid's REST layer hands untrusted JSON bodies to
//! `serde_json::from_str::<FetchedMessage>`-shaped DTOs and the client
//! serializes receipts back out; malformed input must produce an error,
//! never a panic. Run via `make fuzz`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<osci::protocol::FetchedMessage>(s);
        let _ = serde_json::from_str::<osci::protocol::Receipt>(s);
    }
});
