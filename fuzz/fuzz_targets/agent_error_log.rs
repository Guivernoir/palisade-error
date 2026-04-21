#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use palisade_errors::AgentError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Arbitrary, Debug)]
struct LogInput {
    code: u16,
    external: Vec<u8>,
    internal: Vec<u8>,
    sensitive: Vec<u8>,
    repetitions: u8,
}

fn lossy_string(bytes: &[u8]) -> String {
    let truncated = &bytes[..bytes.len().min(256)];
    String::from_utf8_lossy(truncated).into_owned()
}

fn temp_log_path() -> PathBuf {
    let suffix = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "palisade_errors_fuzz_log_{}_{}.log",
        std::process::id(),
        suffix
    ))
}

fn cleanup_log(path: &Path) {
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

fuzz_target!(|input: LogInput| {
    let path = temp_log_path();
    let err = AgentError::new(
        input.code,
        lossy_string(&input.external),
        lossy_string(&input.internal),
        lossy_string(&input.sensitive),
    );

    for _ in 0..=usize::from(input.repetitions.min(3)) {
        err.log(&path).unwrap();
    }

    let metadata = std::fs::metadata(&path).unwrap();
    assert!(metadata.len() > 0);
    cleanup_log(&path);
});
