#[path = "support/mod.rs"]
mod common;

#[cfg(feature = "log")]
use common::{cleanup_log, temp_log_path};
use common::{run_bench_with_ct, write_report};
use palisade_errors::AgentError;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Duration;

fn main() {
    let mut results = Vec::new();

    results.push(run_bench_with_ct(
        "agent_error_new_mem",
        25_000,
        Duration::from_micros(1),
        || {
            let _ = black_box(AgentError::new(100, "external", "internal", "sensitive"));
        },
    ));

    let err = AgentError::new(100, "external", "internal", "sensitive");
    results.push(run_bench_with_ct(
        "agent_error_display_mem",
        50_000,
        Duration::from_micros(1),
        || {
            let mut sink = common::CountingWriter::new();
            write!(&mut sink, "{err}").unwrap();
            black_box(sink.len());
        },
    ));
    results.push(run_bench_with_ct(
        "agent_error_debug_mem",
        50_000,
        Duration::from_micros(1),
        || {
            let mut sink = common::CountingWriter::new();
            write!(&mut sink, "{err:?}").unwrap();
            black_box(sink.len());
        },
    ));
    results.push(run_bench_with_ct(
        "agent_error_timing_norm_mem",
        10_000,
        Duration::from_micros(5),
        || {
            let _ = black_box(
                AgentError::new(103, "external", "internal", "sensitive")
                    .with_timing_normalization(Duration::from_micros(5)),
            );
        },
    ));

    #[cfg(feature = "log")]
    {
        let path = temp_log_path("memory");
        results.push(run_bench_with_ct(
            "agent_error_log_mem",
            1_000,
            Duration::from_micros(1),
            || {
                err.log(&path).unwrap();
                cleanup_log(&path);
            },
        ));
    }

    let path = write_report("memory.txt", "palisade-errors memory benchmark", &results)
        .expect("failed to write memory benchmark report");

    println!("{}", path.display());
}
