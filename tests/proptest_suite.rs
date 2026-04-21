use palisade_errors::AgentError;
use proptest::prelude::*;
#[cfg(feature = "log")]
use std::path::{Path, PathBuf};
#[cfg(feature = "log")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "log")]
static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fuzz_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..128).prop_map(|chars| chars.into_iter().collect())
}

fn tagged_payload(label: &'static str) -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z0-9_.-]{1,32}")
        .expect("tagged payload regex must be valid")
        .prop_map(move |body| format!("<<PALISADE_{label}_{body}>>"))
}

#[cfg(feature = "log")]
fn temp_log_path(label: &str) -> PathBuf {
    let suffix = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "palisade_errors_{label}_{}_{}.log",
        std::process::id(),
        suffix
    ))
}

#[cfg(feature = "log")]
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[cfg(not(feature = "trusted_debug"))]
    #[test]
    fn display_and_debug_show_only_external_payload(
        code in any::<u16>(),
        external in tagged_payload("EXTERNAL"),
        internal in tagged_payload("INTERNAL"),
        sensitive in tagged_payload("SENSITIVE"),
    ) {
        let err = AgentError::new(code, &external, &internal, &sensitive);
        let display = format!("{err}");
        let debug = format!("{err:?}");

        prop_assert_eq!(display.as_str(), external.as_str());
        prop_assert!(debug.contains(&external));
        prop_assert!(!display.contains(&internal));
        prop_assert!(!debug.contains(&internal));
        prop_assert!(!display.contains(&sensitive));
        prop_assert!(!debug.contains(&sensitive));
    }

    #[cfg(feature = "trusted_debug")]
    #[test]
    fn trusted_debug_exposes_full_payloads(
        code in any::<u16>(),
        external in tagged_payload("EXTERNAL"),
        internal in tagged_payload("INTERNAL"),
        sensitive in tagged_payload("SENSITIVE"),
    ) {
        let err = AgentError::new(code, &external, &internal, &sensitive);
        let display = format!("{err}");
        let debug = format!("{err:?}");

        prop_assert_eq!(display.as_str(), external.as_str());
        prop_assert!(debug.contains(&external));
        prop_assert!(debug.contains(&internal));
        prop_assert!(debug.contains(&sensitive));
        prop_assert!(debug.contains("code"));
    }

    #[cfg(feature = "log")]
    #[test]
    fn log_appends_for_arbitrary_payloads(
        code in any::<u16>(),
        external in fuzz_string(),
        internal in fuzz_string(),
        sensitive in fuzz_string(),
    ) {
        let path = temp_log_path("proptest");
        let err = AgentError::new(code, external, internal, sensitive);

        err.log(&path).unwrap();
        let first_len = std::fs::metadata(&path).unwrap().len();
        err.log(&path).unwrap();
        let second_len = std::fs::metadata(&path).unwrap().len();

        prop_assert!(first_len > 0);
        prop_assert!(second_len > first_len);
        cleanup_log(&path);
    }

    #[test]
    fn timing_normalization_respects_requested_floor(
        code in any::<u16>(),
        external in fuzz_string(),
        internal in fuzz_string(),
        sensitive in fuzz_string(),
        millis in 0_u8..=2,
    ) {
        let start = Instant::now();
        let _err = AgentError::new(code, external, internal, sensitive)
            .with_timing_normalization(Duration::from_millis(u64::from(millis)));
        prop_assert!(start.elapsed() >= Duration::from_millis(u64::from(millis)));
    }
}
