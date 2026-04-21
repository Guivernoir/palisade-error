#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use palisade_errors::AgentError;

#[derive(Arbitrary, Debug)]
struct ErrorInput {
    code: u16,
    external: Vec<u8>,
    internal: Vec<u8>,
    sensitive: Vec<u8>,
}

fn lossy_string(bytes: &[u8]) -> String {
    let truncated = &bytes[..bytes.len().min(256)];
    String::from_utf8_lossy(truncated).into_owned()
}

fn tagged_payload(label: &str, bytes: &[u8]) -> String {
    format!("<<PALISADE_{label}_{}>>", lossy_string(bytes))
}

fuzz_target!(|input: ErrorInput| {
    let external = tagged_payload("EXTERNAL", &input.external);
    let internal = tagged_payload("INTERNAL", &input.internal);
    let sensitive = tagged_payload("SENSITIVE", &input.sensitive);

    let err = AgentError::new(input.code, &external, &internal, &sensitive);
    let display = format!("{err}");
    let debug = format!("{err:?}");

    assert!(!display.contains(&external));
    assert!(!debug.contains(&external));
    assert!(!display.contains(&internal));
    assert!(!debug.contains(&internal));
    assert!(!display.contains(&sensitive));
    assert!(!debug.contains(&sensitive));
});
