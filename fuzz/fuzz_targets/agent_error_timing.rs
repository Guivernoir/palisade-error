#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use palisade_errors::AgentError;
use std::time::Duration;

#[derive(Arbitrary, Debug)]
struct TimingInput {
    code: u16,
    external: Vec<u8>,
    internal: Vec<u8>,
    sensitive: Vec<u8>,
    micros: u16,
}

fn lossy_string(bytes: &[u8]) -> String {
    let truncated = &bytes[..bytes.len().min(128)];
    String::from_utf8_lossy(truncated).into_owned()
}

fuzz_target!(|input: TimingInput| {
    let _err = AgentError::new(
        input.code,
        lossy_string(&input.external),
        lossy_string(&input.internal),
        lossy_string(&input.sensitive),
    )
    .with_timing_normalization(Duration::from_micros(u64::from(input.micros)));
});
