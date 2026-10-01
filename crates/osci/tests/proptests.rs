//! Property-based invariants: whatever the world throws at these parsers,
//! they must not panic, and their promises must hold for all inputs, not
//! just the ones we thought of while writing them.

use proptest::prelude::*;

use osci::protocol::Response;
use osci::sniff_root_element;

proptest! {
    /// The bridge reader feeds arbitrary stdout lines into
    /// `serde_json::from_str::<Response>`; garbage must be an Err, never a
    /// panic. This is the parse path every real invocation relies on.
    #[test]
    fn response_parse_never_panics(input in "\\PC*") {
        let _ = serde_json::from_str::<Response>(&input);
    }

    /// Arbitrary XML-ish prologues (declarations, comments, PIs, doctypes,
    /// whitespace, and at most one leading BOM — files carry one, not a
    /// collection) followed by exactly one element must always sniff that
    /// element — and never panic.
    #[test]
    fn sniff_survives_arbitrary_prologues(
        bom in proptest::option::of(Just(())),
        prologue in prologue_strategy(),
        name in "[A-Za-z_][A-Za-z0-9_:\\-]{0,30}",
    ) {
        let mut doc = Vec::new();
        if bom.is_some() {
            doc.extend_from_slice("\u{feff}".as_bytes());
        }
        doc.extend_from_slice(&prologue);
        doc.extend_from_slice(format!("<{name}/>").as_bytes());
        prop_assert_eq!(sniff_root_element(&doc), Some(name.clone()));
    }

    /// Arbitrary byte soup must never panic the sniffer.
    #[test]
    fn sniff_survives_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = sniff_root_element(&bytes);
    }
}

/// Compositions of the XML decorations the sniffer claims to skip (BOM
/// handled separately — see above).
fn prologue_strategy() -> BoxedStrategy<Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            Just("<?xml version=\"1.0\"?>".as_bytes().to_vec()),
            Just("<?pi data?>".as_bytes().to_vec()),
            Just("<!-- kommentar -->".as_bytes().to_vec()),
            Just("<!DOCTYPE XTA SYSTEM \"xta.dtd\">".as_bytes().to_vec()),
            Just(" ".as_bytes().to_vec()),
            Just("\n\t\r".as_bytes().to_vec()),
        ],
        0..6,
    )
    .prop_map(|parts| parts.concat())
    .boxed()
}
