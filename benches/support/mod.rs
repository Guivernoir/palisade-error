use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};
use std::alloc::System;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

pub(crate) struct BenchResult {
    pub(crate) name: &'static str,
    pub(crate) iterations: usize,
    pub(crate) total: Duration,
    pub(crate) min: Duration,
    pub(crate) max: Duration,
    pub(crate) stats: Stats,
    pub(crate) ct_floor: Option<Duration>,
    pub(crate) ct_ok: Option<bool>,
}

pub(crate) struct CountingWriter {
    len: usize,
}

impl CountingWriter {
    pub(crate) fn new() -> Self {
        Self { len: 0 }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }
}

impl fmt::Write for CountingWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.len += s.len();
        Ok(())
    }
}

pub(crate) fn run_bench(
    name: &'static str,
    iterations: usize,
    mut scenario: impl FnMut(),
) -> BenchResult {
    let mut total = Duration::ZERO;
    let mut min = Duration::MAX;
    let mut max = Duration::ZERO;
    let mut stats = Stats::default();

    for _ in 0..iterations {
        let region = Region::new(GLOBAL);
        let start = Instant::now();
        scenario();
        let elapsed = start.elapsed();
        let sample = region.change();

        total += elapsed;
        min = min.min(elapsed);
        max = max.max(elapsed);
        accumulate(&mut stats, sample);
    }

    BenchResult {
        name,
        iterations,
        total,
        min,
        max,
        stats,
        ct_floor: None,
        ct_ok: None,
    }
}

pub(crate) fn run_bench_with_ct(
    name: &'static str,
    iterations: usize,
    ct_floor: Duration,
    scenario: impl FnMut(),
) -> BenchResult {
    let mut result = run_bench(name, iterations, scenario);
    result.ct_ok = Some(result.min >= ct_floor);
    result.ct_floor = Some(ct_floor);
    result
}

pub(crate) fn write_report(
    file_name: &str,
    title: &str,
    results: &[BenchResult],
) -> std::io::Result<PathBuf> {
    let report_dir = Path::new("target/bench-results");
    fs::create_dir_all(report_dir)?;
    let path = report_dir.join(file_name);

    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    let mut out = String::new();
    out.push_str(title);
    out.push('\n');
    out.push_str(&format!("generated_at_unix={generated_at}\n\n"));

    for result in results {
        let avg_ns = result.total.as_nanos() / result.iterations as u128;
        out.push_str(&format!("scenario={}\n", result.name));
        out.push_str(&format!("iterations={}\n", result.iterations));
        out.push_str(&format!("avg_ns={avg_ns}\n"));
        out.push_str(&format!("min_ns={}\n", result.min.as_nanos()));
        out.push_str(&format!("max_ns={}\n", result.max.as_nanos()));
        out.push_str(&format!(
            "allocations_per_iter={}\n",
            result.stats.allocations / result.iterations
        ));
        out.push_str(&format!(
            "deallocations_per_iter={}\n",
            result.stats.deallocations / result.iterations
        ));
        out.push_str(&format!(
            "reallocations_per_iter={}\n",
            result.stats.reallocations / result.iterations
        ));
        out.push_str(&format!(
            "bytes_allocated_per_iter={}\n",
            result.stats.bytes_allocated / result.iterations
        ));
        out.push_str(&format!(
            "bytes_deallocated_per_iter={}\n",
            result.stats.bytes_deallocated / result.iterations
        ));
        out.push_str(&format!(
            "bytes_reallocated_per_iter={}\n\n",
            result.stats.bytes_reallocated / result.iterations as isize
        ));
        if let Some(ct_floor) = result.ct_floor {
            out.push_str(&format!("ct_floor_ns={}\n", ct_floor.as_nanos()));
            out.push_str(&format!(
                "ct_ok={}\n\n",
                result
                    .ct_ok
                    .expect("ct result must be present when ct floor is set")
            ));
        }
    }

    fs::write(&path, out)?;
    Ok(path)
}

#[cfg(feature = "log")]
pub(crate) fn temp_log_path(label: &str) -> PathBuf {
    Path::new("target/bench-results").join(format!(
        "palisade_errors_{label}_{}_{}.log",
        std::process::id(),
        monotonic_suffix(),
    ))
}

#[cfg(feature = "log")]
pub(crate) fn cleanup_log(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "log")]
fn monotonic_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn accumulate(total: &mut Stats, sample: Stats) {
    total.allocations += sample.allocations;
    total.deallocations += sample.deallocations;
    total.reallocations += sample.reallocations;
    total.bytes_allocated += sample.bytes_allocated;
    total.bytes_deallocated += sample.bytes_deallocated;
    total.bytes_reallocated += sample.bytes_reallocated;
}
