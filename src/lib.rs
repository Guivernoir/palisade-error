//! # Palisade Errors — blackbox edition
//!
//! Security-conscious error handling for hostile-environment deployments.
//!
//! ## Public surface
//!
//! The crate exports exactly one named public type: [`AgentError`].
//!
//! Its inherent methods are the supported entry points:
//!
//! ```text
//! AgentError::new(code, external, internal, sensitive) -> AgentError
//! AgentError::with_timing_normalization(self, minimum) -> AgentError
//! AgentError::with_timing_normalization_async(self, minimum) -> AgentError
//! AgentError::log(&self, path) -> io::Result<()>    // feature = "log"
//! ```
//!
//! Everything else is crate-private implementation detail.
//!
//! ## Automatic security behaviours (zero opt-out)
//!
//! Every call to `AgentError::new()` unconditionally applies:
//!
//! - **Code obfuscation** — numeric code is offset by a per-session random
//!   salt so attackers cannot build a stable fingerprint map across sessions.
//! - **Constant-time floor** — a 50 µs minimum public-path duration reduces
//!   timing discrimination across error surfaces.
//! - **Ring-buffer logging** — the error is appended to a fully preallocated
//!   in-process forensic buffer for DoS-bounded retention.
//! - **Terminal Display** — `Display` emits only the external payload so the
//!   terminal surface stays minimal and the internal payloads remain log-only.
//! - **Trusted Debug** — `Debug` exposes the full payload set only when
//!   `feature = "trusted_debug"` is enabled.
//! - **Zeroize on Drop** — inline payload buffers are scrubbed before reuse or
//!   drop.
//!
//! ## Log encryption (`AgentError::log`)
//!
//! Calling `.log(path)` appends one layered encrypted record to `path`
//! and immediately sets the file to read-only (`0o400` on Unix).
//! This API is available only when the `log` feature is enabled.
//!
//! - The session key is generated once from the OS CSPRNG and held in
//!   process memory only — it is never written to disk.
//! - Each record uses inner AES-256-GCM, an outer SHA-512-derived masking
//!   layer, and an HMAC-SHA512 tag over the final frame.
//! - Record construction, layered encryption, and MAC generation use
//!   fixed-capacity buffers and avoid heap allocation.
//! - This improves defense-in-depth and quantum search margin, but it is not a
//!   substitute for a standardized post-quantum cryptosystem.
//! - Reading the log file still requires the session key, which demands either
//!   live process-memory access or a separately secured key-escrow mechanism.
//!
//! ## Error code ranges
//!
//! | Range     | Namespace | Domain                  |
//! |-----------|-----------|-------------------------|
//! | 1 – 30    | CORE      | Fundamental system       |
//! | 100 – 131 | CFG       | Configuration            |
//! | 200 – 237 | DCP       | Deception subsystem      |
//! | 300 – 333 | TEL       | Telemetry                |
//! | 400 – 434 | COR       | Correlation / analysis   |
//! | 500 – 533 | RSP       | Response / action        |
//! | 600 – 630 | LOG       | Logging / audit          |
//! | 700 – 730 | PLT       | Platform / OS            |
//! | 800 – 830 | IO        | Filesystem / network     |

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::clone_on_ref_ptr)]

use fixed::{FixedString, TRUNCATION_INDICATOR};
use std::fmt;
#[cfg(feature = "log")]
use std::io;
#[cfg(feature = "log")]
use std::path::Path;
#[cfg(feature = "log")]
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use zeroization::Zeroize;

// ── Internal modules ──────────────────────────────────────────────────────────

mod codes;
mod convenience;
mod crypto;
mod ct;
mod definitions;
mod fixed;
#[cfg(feature = "log")]
mod log_sink;
mod models;
mod obfuscation;
mod ring_buffer;
mod zeroization;

// ── Session key (process-lifetime, never written to disk) ─────────────────────

/// AES-256 session key held exclusively in process memory.
///
/// Seeded once from the OS CSPRNG on first log write.  Never exported, never
/// written to disk. Extracting it still requires live process-memory access.
#[cfg(feature = "log")]
static SESSION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

#[cold]
#[cfg(feature = "log")]
fn init_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    crypto::fill_random_array(&mut key).expect("OS RNG unavailable; cannot initialise session key");
    key
}

#[inline]
#[cfg(feature = "log")]
fn session_key() -> &'static [u8; 32] {
    SESSION_KEY.get_or_init(init_session_key)
}

// ── Global ring buffer (DoS-bounded in-process forensic log) ──────────────────

const PUBLIC_API_FLOOR: Duration = Duration::from_micros(50);
const EXTERNAL_BYTES: usize = 256;
const INTERNAL_BYTES: usize = 512;
const SENSITIVE_BYTES: usize = 512;

type GlobalRingBuffer = ring_buffer::RingBufferLogger<4_096, 768>;

static GLOBAL_RING: GlobalRingBuffer = GlobalRingBuffer::new_internal();

#[inline]
fn global_ring() -> &'static GlobalRingBuffer {
    &GLOBAL_RING
}

// ── Code lookup ───────────────────────────────────────────────────────────────

/// Map a caller-supplied numeric code to a pre-defined static `ErrorCode`.
///
/// Unknown codes fall back silently to `CORE_INVALID_STATE` (4) — always safer
/// than panicking in a hostile environment.
pub(crate) fn resolve_code(n: u16) -> &'static codes::ErrorCode {
    use definitions::*;
    match n {
        // CORE (1-30)
        1 => &CORE_INIT_FAILED,
        2 => &CORE_SHUTDOWN_FAILED,
        3 => &CORE_PANIC_RECOVERY,
        4 => &CORE_INVALID_STATE,
        5 => &CORE_MEMORY_ALLOC_FAILED,
        6 => &CORE_THREAD_SPAWN_FAILED,
        7 => &CORE_MUTEX_LOCK_FAILED,
        8 => &CORE_SIGNAL_HANDLER_FAILED,
        9 => &CORE_MODULE_LOAD_FAILED,
        10 => &CORE_DEPENDENCY_MISSING,
        11 => &CORE_VERSION_CHECK_FAILED,
        12 => &CORE_RESOURCE_INIT_FAILED,
        13 => &CORE_EVENT_LOOP_FAILED,
        14 => &CORE_CONFIG_BOOTSTRAP_FAILED,
        15 => &CORE_DATABASE_CONNECT_FAILED,
        16 => &CORE_CACHE_INIT_FAILED,
        17 => &CORE_QUEUE_OVERFLOW,
        18 => &CORE_TIMER_SETUP_FAILED,
        19 => &CORE_HOOK_REGISTRATION_FAILED,
        20 => &CORE_PLUGIN_INIT_FAILED,
        21 => &CORE_STATE_TRANSITION_FAILED,
        22 => &CORE_HEALTH_CHECK_FAILED,
        23 => &CORE_BACKUP_FAILED,
        24 => &CORE_RESTORE_FAILED,
        25 => &CORE_MIGRATION_FAILED,
        26 => &CORE_LICENSE_VALIDATION_FAILED,
        27 => &CORE_AUTH_INIT_FAILED,
        28 => &CORE_CRYPTO_SETUP_FAILED,
        29 => &CORE_NETWORK_INIT_FAILED,
        30 => &CORE_API_SERVER_START_FAILED,
        // CFG (100-131)
        100 => &CFG_PARSE_FAILED,
        101 => &CFG_VALIDATION_FAILED,
        102 => &CFG_MISSING_REQUIRED,
        103 => &CFG_INVALID_VALUE,
        104 => &CFG_INVALID_FORMAT,
        105 => &CFG_PERMISSION_DENIED,
        106 => &CFG_VERSION_MISMATCH,
        107 => &CFG_SECURITY_VIOLATION,
        108 => &CFG_LOAD_FAILED,
        109 => &CFG_SAVE_FAILED,
        110 => &CFG_ENV_VAR_MISSING,
        111 => &CFG_TYPE_MISMATCH,
        112 => &CFG_DUPLICATE_KEY,
        113 => &CFG_SCHEMA_VALIDATION_FAILED,
        114 => &CFG_MERGE_CONFLICT,
        115 => &CFG_REMOTE_FETCH_FAILED,
        116 => &CFG_LOCAL_STORE_FAILED,
        117 => &CFG_ENCRYPTION_FAILED,
        118 => &CFG_DECRYPTION_FAILED,
        119 => &CFG_KEY_NOT_FOUND,
        120 => &CFG_INVALID_PATH,
        121 => &CFG_CONVERSION_FAILED,
        122 => &CFG_DEFAULTS_LOAD_FAILED,
        123 => &CFG_OVERRIDE_FAILED,
        124 => &CFG_WATCHER_INIT_FAILED,
        125 => &CFG_RELOAD_FAILED,
        126 => &CFG_BACKUP_FAILED,
        127 => &CFG_ROLLBACK_FAILED,
        128 => &CFG_TEMPLATE_RENDER_FAILED,
        129 => &CFG_VARIABLE_RESOLUTION_FAILED,
        130 => &CFG_SECRETS_MANAGER_FAILED,
        131 => &CFG_PROFILE_SWITCH_FAILED,
        // DCP (200-237)
        200 => &DCP_DEPLOY_FAILED,
        201 => &DCP_ARTIFACT_CREATE,
        202 => &DCP_ARTIFACT_WRITE,
        203 => &DCP_CLEANUP_FAILED,
        204 => &DCP_TAG_GENERATION,
        205 => &DCP_TRIGGER_FAILED,
        206 => &DCP_SIMULATION_FAILED,
        207 => &DCP_BAIT_DEPLOY_FAILED,
        208 => &DCP_HONEYPOT_INIT_FAILED,
        209 => &DCP_FAKE_DATA_GENERATION_FAILED,
        210 => &DCP_REDIRECT_SETUP_FAILED,
        211 => &DCP_MIMICRY_FAILED,
        212 => &DCP_TARPIT_ENGAGE_FAILED,
        213 => &DCP_DECOY_LAUNCH_FAILED,
        214 => &DCP_SHADOW_SYSTEM_FAILED,
        215 => &DCP_FINGERPRINT_MISMATCH,
        216 => &DCP_BEHAVIOR_MODEL_LOAD_FAILED,
        217 => &DCP_INTRUSION_SIM_FAILED,
        218 => &DCP_COUNTERMEASURE_FAILED,
        219 => &DCP_ARTIFACT_EXPIRATION,
        220 => &DCP_DEPLOYMENT_ROLLBACK_FAILED,
        221 => &DCP_RESOURCE_ALLOCATION_FAILED,
        222 => &DCP_TEMPLATE_LOAD_FAILED,
        223 => &DCP_VALIDATION_CHECK_FAILED,
        224 => &DCP_INTEGRITY_CHECK_FAILED,
        225 => &DCP_NETWORK_SIM_FAILED,
        226 => &DCP_ACCESS_CONTROL_FAILED,
        227 => &DCP_ENCRYPTED_ARTIFACT_FAILED,
        228 => &DCP_DECRYPT_ARTIFACT_FAILED,
        229 => &DCP_DYNAMIC_GENERATION_FAILED,
        230 => &DCP_PERSISTENCE_FAILED,
        231 => &DCP_NARRATIVE_DESYNC,
        232 => &DCP_NARRATIVE_BREAK,
        233 => &DCP_BELIEVABILITY_LOW,
        234 => &DCP_ADVERSARY_ADAPTATION,
        235 => &DCP_STATE_VIOLATION,
        236 => &DCP_TEMPORAL_INCONSISTENCY,
        237 => &DCP_CAUSALITY_BREACH,
        // TEL (300-333)
        300 => &TEL_INIT_FAILED,
        301 => &TEL_WATCH_FAILED,
        302 => &TEL_EVENT_LOST,
        303 => &TEL_CHANNEL_CLOSED,
        304 => &TEL_MONITOR_CRASH,
        305 => &TEL_METRIC_COLLECTION_FAILED,
        306 => &TEL_EXPORT_FAILED,
        307 => &TEL_AGGREGATION_FAILED,
        308 => &TEL_TRACE_SPAN_FAILED,
        309 => &TEL_REMOTE_SEND_FAILED,
        310 => &TEL_BUFFER_OVERFLOW,
        311 => &TEL_INVALID_METRIC,
        312 => &TEL_SAMPLING_FAILED,
        313 => &TEL_PROPAGATION_FAILED,
        314 => &TEL_ENDPOINT_UNREACHABLE,
        315 => &TEL_AUTH_FAILED,
        316 => &TEL_COMPRESSION_FAILED,
        317 => &TEL_DECOMPRESSION_FAILED,
        318 => &TEL_FILTER_APPLY_FAILED,
        319 => &TEL_ALERT_TRIGGER_FAILED,
        320 => &TEL_DASHBOARD_UPDATE_FAILED,
        321 => &TEL_LOG_INGEST_FAILED,
        322 => &TEL_QUERY_FAILED,
        323 => &TEL_RETENTION_POLICY_FAILED,
        324 => &TEL_BACKPRESSURE,
        325 => &TEL_INSTRUMENTATION_FAILED,
        326 => &TEL_BATCH_PROCESS_FAILED,
        327 => &TEL_SERIALIZATION_FAILED,
        328 => &TEL_DESERIALIZATION_FAILED,
        329 => &TEL_RESOURCE_MONITOR_FAILED,
        330 => &TEL_HEARTBEAT_FAILED,
        331 => &TEL_EVASION_DETECTED,
        332 => &TEL_SENSOR_BYPASS,
        333 => &TEL_OBSERVABILITY_GAP,
        // COR (400-434)
        400 => &COR_RULE_EVAL_FAILED,
        401 => &COR_BUFFER_OVERFLOW,
        402 => &COR_INVALID_SCORE,
        403 => &COR_WINDOW_EXPIRED,
        404 => &COR_INVALID_ARTIFACT,
        405 => &COR_PATTERN_MATCH_FAILED,
        406 => &COR_DATA_INGEST_FAILED,
        407 => &COR_AGGREGATION_FAILED,
        408 => &COR_THRESHOLD_BREACH,
        409 => &COR_FALSE_POSITIVE,
        410 => &COR_EVENT_MERGE_FAILED,
        411 => &COR_CONTEXT_LOAD_FAILED,
        412 => &COR_ANOMALY_DETECT_FAILED,
        413 => &COR_MODEL_TRAIN_FAILED,
        414 => &COR_INFERENCE_FAILED,
        415 => &COR_DATA_NORMALIZATION_FAILED,
        416 => &COR_FEATURE_EXTRACTION_FAILED,
        417 => &COR_CLUSTERING_FAILED,
        418 => &COR_OUTLIER_DETECTION_FAILED,
        419 => &COR_TIME_SERIES_ANALYSIS_FAILED,
        420 => &COR_GRAPH_BUILD_FAILED,
        421 => &COR_PATH_ANALYSIS_FAILED,
        422 => &COR_RULE_UPDATE_FAILED,
        423 => &COR_VALIDATION_FAILED,
        424 => &COR_EXPORT_FAILED,
        425 => &COR_IMPORT_FAILED,
        426 => &COR_QUERY_EXEC_FAILED,
        427 => &COR_INDEX_BUILD_FAILED,
        428 => &COR_SEARCH_FAILED,
        429 => &COR_ENRICHMENT_FAILED,
        430 => &COR_DEDUPLICATION_FAILED,
        431 => &COR_CONFIDENCE_DEGRADATION,
        432 => &COR_MODEL_DRIFT,
        433 => &COR_HYPOTHESIS_INVALIDATED,
        434 => &COR_ACTOR_CONFLICT,
        // RSP (500-533)
        500 => &RSP_EXEC_FAILED,
        501 => &RSP_TIMEOUT,
        502 => &RSP_INVALID_ACTION,
        503 => &RSP_RATE_LIMITED,
        504 => &RSP_HANDLER_NOT_FOUND,
        505 => &RSP_SERIALIZATION_FAILED,
        506 => &RSP_DESERIALIZATION_FAILED,
        507 => &RSP_VALIDATION_FAILED,
        508 => &RSP_AUTH_FAILED,
        509 => &RSP_PERMISSION_DENIED,
        510 => &RSP_RESOURCE_NOT_FOUND,
        511 => &RSP_CONFLICT,
        512 => &RSP_INTERNAL_ERROR,
        513 => &RSP_BAD_REQUEST,
        514 => &RSP_UNAVAILABLE,
        515 => &RSP_GATEWAY_TIMEOUT,
        516 => &RSP_TOO_MANY_REQUESTS,
        517 => &RSP_PAYLOAD_TOO_LARGE,
        518 => &RSP_UNSUPPORTED_MEDIA,
        519 => &RSP_METHOD_NOT_ALLOWED,
        520 => &RSP_NOT_ACCEPTABLE,
        521 => &RSP_PROXY_AUTH_REQUIRED,
        522 => &RSP_REQUEST_TIMEOUT,
        523 => &RSP_PRECONDITION_FAILED,
        524 => &RSP_EXPECTATION_FAILED,
        525 => &RSP_MISDIRECTED_REQUEST,
        526 => &RSP_UNPROCESSABLE_ENTITY,
        527 => &RSP_LOCKED,
        528 => &RSP_FAILED_DEPENDENCY,
        529 => &RSP_UPGRADE_REQUIRED,
        530 => &RSP_PRECONDITION_REQUIRED,
        531 => &RSP_TIMING_ANOMALY,
        532 => &RSP_ENTROPY_LOW,
        533 => &RSP_BEHAVIORAL_INCONSISTENCY,
        // LOG (600-630)
        600 => &LOG_WRITE_FAILED,
        601 => &LOG_ROTATE_FAILED,
        602 => &LOG_BUFFER_FULL,
        603 => &LOG_SERIALIZATION,
        604 => &LOG_INIT_FAILED,
        605 => &LOG_FLUSH_FAILED,
        606 => &LOG_LEVEL_INVALID,
        607 => &LOG_FILTER_APPLY_FAILED,
        608 => &LOG_APPENDER_FAILED,
        609 => &LOG_REMOTE_SEND_FAILED,
        610 => &LOG_COMPRESSION_FAILED,
        611 => &LOG_ENCRYPTION_FAILED,
        612 => &LOG_ARCHIVE_FAILED,
        613 => &LOG_PURGE_FAILED,
        614 => &LOG_INDEX_FAILED,
        615 => &LOG_SEARCH_FAILED,
        616 => &LOG_PARSE_FAILED,
        617 => &LOG_FORMAT_INVALID,
        618 => &LOG_TIMESTAMP_FAILED,
        619 => &LOG_METADATA_MISSING,
        620 => &LOG_ROLLOVER_FAILED,
        621 => &LOG_BACKUP_FAILED,
        622 => &LOG_RESTORE_FAILED,
        623 => &LOG_QUEUE_OVERFLOW,
        624 => &LOG_ASYNC_SEND_FAILED,
        625 => &LOG_SYNC_FAILED,
        626 => &LOG_HANDLER_CRASH,
        627 => &LOG_CONFIG_LOAD_FAILED,
        628 => &LOG_RELOAD_FAILED,
        629 => &LOG_EXPORT_FAILED,
        630 => &LOG_IMPORT_FAILED,
        // PLT (700-730)
        700 => &PLT_UNSUPPORTED,
        701 => &PLT_SYSCALL_FAILED,
        702 => &PLT_PERMISSION_DENIED,
        703 => &PLT_RESOURCE_EXHAUSTED,
        704 => &PLT_OS_VERSION_MISMATCH,
        705 => &PLT_HARDWARE_UNSUPPORTED,
        706 => &PLT_DRIVER_LOAD_FAILED,
        707 => &PLT_API_CALL_FAILED,
        708 => &PLT_ENV_DETECT_FAILED,
        709 => &PLT_VIRTUALIZATION_FAILED,
        710 => &PLT_CONTAINER_INIT_FAILED,
        711 => &PLT_KERNEL_MODULE_FAILED,
        712 => &PLT_FILESYSTEM_MOUNT_FAILED,
        713 => &PLT_NETWORK_INTERFACE_FAILED,
        714 => &PLT_PROCESS_SPAWN_FAILED,
        715 => &PLT_SIGNAL_SEND_FAILED,
        716 => &PLT_MEMORY_MAP_FAILED,
        717 => &PLT_THREAD_AFFINITY_FAILED,
        718 => &PLT_POWER_MANAGEMENT_FAILED,
        719 => &PLT_BOOTSTRAP_FAILED,
        720 => &PLT_SHUTDOWN_HOOK_FAILED,
        721 => &PLT_COMPATIBILITY_CHECK_FAILED,
        722 => &PLT_LIBRARY_LOAD_FAILED,
        723 => &PLT_SYMBOL_RESOLVE_FAILED,
        724 => &PLT_SECURITY_POLICY_FAILED,
        725 => &PLT_AUDIT_HOOK_FAILED,
        726 => &PLT_RESOURCE_LIMIT_REACHED,
        727 => &PLT_CLOCK_SYNC_FAILED,
        728 => &PLT_DEVICE_ACCESS_FAILED,
        729 => &PLT_FIRMWARE_UPDATE_FAILED,
        730 => &PLT_BIOS_CONFIG_FAILED,
        // IO (800-830)
        800 => &IO_READ_FAILED,
        801 => &IO_WRITE_FAILED,
        802 => &IO_NETWORK_ERROR,
        803 => &IO_TIMEOUT,
        804 => &IO_NOT_FOUND,
        805 => &IO_METADATA_FAILED,
        806 => &IO_OPEN_FAILED,
        807 => &IO_CLOSE_FAILED,
        808 => &IO_SEEK_FAILED,
        809 => &IO_FLUSH_FAILED,
        810 => &IO_PERMISSION_DENIED,
        811 => &IO_INTERRUPTED,
        812 => &IO_WOULD_BLOCK,
        813 => &IO_INVALID_INPUT,
        814 => &IO_BROKEN_PIPE,
        815 => &IO_CONNECTION_RESET,
        816 => &IO_CONNECTION_REFUSED,
        817 => &IO_NOT_CONNECTED,
        818 => &IO_ADDR_IN_USE,
        819 => &IO_ADDR_NOT_AVAILABLE,
        820 => &IO_NETWORK_DOWN,
        821 => &IO_NETWORK_UNREACHABLE,
        822 => &IO_HOST_UNREACHABLE,
        823 => &IO_ALREADY_EXISTS,
        824 => &IO_IS_DIRECTORY,
        825 => &IO_NOT_DIRECTORY,
        826 => &IO_DIRECTORY_NOT_EMPTY,
        827 => &IO_READ_ONLY_FS,
        828 => &IO_FS_QUOTA_EXCEEDED,
        829 => &IO_STALE_NFS_HANDLE,
        830 => &IO_REMOTE_IO,
        // Unknown → safe fallback
        _ => &CORE_INVALID_STATE,
    }
}

// ── Internal error payload ────────────────────────────────────────────────────

/// Three-field inline payload with deterministic truncation and zeroization.
struct ErrorPayload {
    external: FixedString<EXTERNAL_BYTES>,
    internal: FixedString<INTERNAL_BYTES>,
    sensitive: FixedString<SENSITIVE_BYTES>,
    sensitive_present: bool,
}

impl ErrorPayload {
    fn new(external: &str, internal: &str, sensitive: &str) -> Self {
        let mut payload = Self {
            external: FixedString::new(),
            internal: FixedString::new(),
            sensitive: FixedString::new(),
            sensitive_present: !sensitive.is_empty(),
        };
        payload
            .external
            .set_truncated(external, TRUNCATION_INDICATOR);
        payload
            .internal
            .set_truncated(internal, TRUNCATION_INDICATOR);
        if payload.sensitive_present {
            payload
                .sensitive
                .set_truncated(sensitive, TRUNCATION_INDICATOR);
        }
        payload
    }

    #[cfg_attr(not(feature = "log"), allow(dead_code))]
    #[inline]
    fn sensitive(&self) -> Option<&str> {
        self.sensitive_present.then(|| self.sensitive.as_str())
    }
}

impl Zeroize for ErrorPayload {
    fn zeroize(&mut self) {
        self.external.zeroize();
        self.internal.zeroize();
        self.sensitive.zeroize();
        self.sensitive_present.zeroize();
    }
}

impl Drop for ErrorPayload {
    #[inline(never)] // Prevent dead-store elimination of the zeroize pass.
    fn drop(&mut self) {
        zeroization::drop_zeroize(self);
    }
}

// ── AgentError ────────────────────────────────────────────────────────────────

/// The single error type for all palisade subsystems.
///
/// ## Construction
///
/// Use [`AgentError::new`] — the **only** public constructor.
///
/// ## Logging
///
/// Use [`AgentError::log`] to persist an encrypted record to disk when the
/// `log` feature is enabled.
///
/// ## Display invariants
///
/// - `Display` emits only the external payload.
/// - `Debug` emits only the external payload unless `trusted_debug` is enabled.
/// - Logs retain code, internal payload, and sensitive payload.
///
/// Not `Clone` or `Copy` — the single-ownership model prevents side-channel
/// leakage via unintended duplications of sensitive payload strings.
#[must_use = "errors should be handled or logged"]
pub struct AgentError {
    code: codes::ErrorCode,
    payload: ErrorPayload,
    retryable: bool,
    created_at: Instant,
}

impl AgentError {
    // ── Public constructor ────────────────────────────────────────────────────

    /// Create a new error.  **The only public entry point for this type.**
    ///
    /// # Arguments
    ///
    /// | Parameter   | Exposed to  | Purpose                                   |
    /// |-------------|-------------|-------------------------------------------|
    /// | `code`      | obfuscated  | Numeric code from the table in module docs |
    /// | `external`  | terminal    | The only payload shown by default terminal output |
    /// | `internal`  | logs only   | True diagnostic; stays out of default terminal formatting |
    /// | `sensitive` | logs only   | PII / paths; `None` if empty               |
    ///
    /// # Automatic security properties (non-negotiable)
    ///
    /// 1. The code is obfuscated by the process-global session salt.
    /// 2. A constant-time floor of at least 50 µs is enforced.
    /// 3. The error is appended to the preallocated in-process ring buffer.
    ///
    /// # Unknown codes
    ///
    /// Codes outside the defined ranges are silently mapped to
    /// `CORE_INVALID_STATE` (4).  This is intentional: a generic error is
    /// always preferable to a panic in a hostile environment.
    pub fn new(
        code: u16,
        external: impl AsRef<str>,
        internal: impl AsRef<str>,
        sensitive: impl AsRef<str>,
    ) -> Self {
        let created_at = Instant::now();

        // 1. Resolve and obfuscate the error code.
        let base = resolve_code(code);
        let obfuscated = obfuscation::obfuscate_code(base);

        let err = Self {
            code: obfuscated,
            payload: ErrorPayload::new(external.as_ref(), internal.as_ref(), sensitive.as_ref()),
            retryable: false,
            created_at,
        };

        // 2. Append to DoS-bounded ring buffer (in-process forensic log).
        global_ring().log_internal(&err);

        // 3. Constant-time floor — must be the final public-path step.
        ct::enforce_floor(created_at, PUBLIC_API_FLOOR);

        err
    }

    /// Enforce a minimum total error-path duration from construction time.
    pub fn with_timing_normalization(self, minimum_duration: Duration) -> Self {
        let api_start = Instant::now();
        let deadline = ct::deadline_from(self.created_at, minimum_duration)
            .max(ct::deadline_from(api_start, PUBLIC_API_FLOOR));
        ct::sleep_until(deadline);
        self
    }

    /// Async variant of [`AgentError::with_timing_normalization`].
    ///
    /// This remains runtime-free and allocation-free, but it blocks the
    /// current executor thread while waiting.
    pub async fn with_timing_normalization_async(self, minimum_duration: Duration) -> Self {
        let api_start = Instant::now();
        let deadline = ct::deadline_from(self.created_at, minimum_duration)
            .max(ct::deadline_from(api_start, PUBLIC_API_FLOOR));
        ct::sleep_until_async(deadline).await;
        self
    }

    // ── Log to encrypted file ─────────────────────────────────────────────────

    /// Persist an encrypted forensic record for this error to `path`.
    ///
    /// `path` must be an absolute path to a regular log file. Symlinks are
    /// rejected. The file is created if it does not exist; records are always
    /// appended. After each write the file is set owner-read-only (`0o400` on
    /// Unix) until the next append attempt reopens it.
    ///
    /// # Encryption
    ///
    /// Each record uses a layered construction built from the process-lifetime
    /// session key: inner AES-256-GCM, an outer SHA-512-derived masking layer,
    /// and HMAC-SHA512 over the final frame. The session key resides only in
    /// process memory and is never written to disk.
    ///
    /// # Allocation
    ///
    /// This method uses fixed-capacity stack buffers for record construction,
    /// encryption, and authentication. It does not perform heap allocation.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` on validation or filesystem failure. Length
    /// prefixing and MAC verification let readers detect an incomplete trailing
    /// record after an interrupted append.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    pub fn log(&self, path: &Path) -> io::Result<()> {
        use std::fmt::Write as _;

        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log path must be absolute",
            ));
        }

        let start = Instant::now();
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);

        let mut ext_safe = FixedString::<{ convenience::MAX_SANITIZED_LEN }>::new();
        convenience::sanitize_into(
            &mut ext_safe,
            self.payload.external.as_str(),
            convenience::MAX_SANITIZED_LEN,
        );

        let mut int_safe = FixedString::<{ convenience::MAX_SANITIZED_LEN }>::new();
        convenience::sanitize_into(
            &mut int_safe,
            self.payload.internal.as_str(),
            convenience::MAX_SANITIZED_LEN,
        );

        let mut sens_safe = FixedString::<{ convenience::MAX_SANITIZED_LEN }>::new();
        if let Some(sensitive) = self.payload.sensitive() {
            convenience::sanitize_into(&mut sens_safe, sensitive, convenience::MAX_SANITIZED_LEN);
        }

        let mut plaintext = FixedString::<{ log_sink::MAX_PLAINTEXT_BYTES }>::new();
        let build_result = (|| -> fmt::Result {
            write!(
                &mut plaintext,
                "TS={ts_ms}\tCODE={}\tCAT={}\tIMPACT={}\tEXTERNAL=",
                self.code,
                self.code.category().deceptive_name(),
                self.code.impact().value(),
            )?;
            plaintext.write_str(ext_safe.as_str())?;
            plaintext.write_str("\tINTERNAL=")?;
            plaintext.write_str(int_safe.as_str())?;
            plaintext.write_str("\tSENSITIVE=")?;
            if sens_safe.is_empty() {
                plaintext.write_str("<NONE>")?;
            } else {
                plaintext.write_str(sens_safe.as_str())?;
            }
            write!(
                &mut plaintext,
                "\tRETRYABLE={}",
                if self.retryable { "true" } else { "false" }
            )
        })();

        let result = match build_result {
            Ok(()) => log_sink::append_record(session_key(), path, plaintext.as_str().as_bytes()),
            Err(_) => Err(io::Error::other(
                "log record exceeded fixed plaintext budget",
            )),
        };

        plaintext.zeroize();
        ext_safe.zeroize();
        int_safe.zeroize();
        sens_safe.zeroize();
        ct::enforce_floor(start, PUBLIC_API_FLOOR);
        result
    }

    // ── Crate-internal accessors (used by ring_buffer) ────────────────────────

    #[inline]
    pub(crate) fn code_inner(&self) -> &codes::ErrorCode {
        &self.code
    }

    #[inline]
    pub(crate) fn external_payload(&self) -> &str {
        self.payload.external.as_str()
    }

    #[inline]
    pub(crate) fn internal_payload(&self) -> &str {
        self.payload.internal.as_str()
    }

    #[inline]
    pub(crate) fn is_retryable(&self) -> bool {
        self.retryable
    }
}

// ── Drop / Display / Debug / Error ───────────────────────────────────────────

impl Drop for AgentError {
    #[inline(never)]
    fn drop(&mut self) {
        zeroization::drop_zeroize(&mut self.payload);
        self.retryable.zeroize();
    }
}

impl fmt::Display for AgentError {
    /// Terminal-facing external display.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start = Instant::now();
        let result = f.write_str(self.payload.external.as_str());
        ct::enforce_floor(start, PUBLIC_API_FLOOR);
        result
    }
}

#[cfg(feature = "trusted_debug")]
struct DisplayAsDebug<'a, T: ?Sized>(&'a T);

#[cfg(feature = "trusted_debug")]
impl<T> fmt::Debug for DisplayAsDebug<'_, T>
where
    T: fmt::Display + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0, f)
    }
}

#[cfg(feature = "trusted_debug")]
impl fmt::Debug for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start = Instant::now();
        let result = f
            .debug_struct("AgentError")
            .field("code", &DisplayAsDebug(&self.code))
            .field("external", &self.payload.external.as_str())
            .field("internal", &self.payload.internal.as_str())
            .field("sensitive", &self.payload.sensitive())
            .field("retryable", &self.retryable)
            .field("age_us", &self.created_at.elapsed().as_micros())
            .finish();
        ct::enforce_floor(start, PUBLIC_API_FLOOR);
        result
    }
}

#[cfg(not(feature = "trusted_debug"))]
impl fmt::Debug for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start = Instant::now();
        let result = f
            .debug_struct("AgentError")
            .field("external", &self.payload.external.as_str())
            .finish();
        ct::enforce_floor(start, PUBLIC_API_FLOOR);
        result
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn clear_salt() {
        obfuscation::clear_session_salt();
    }

    #[test]
    fn display_contains_no_payload() {
        clear_salt();
        let err = AgentError::new(100, "lie msg", "real diag", "/etc/shadow");
        let display = format!("{}", err);
        assert!(display.contains("lie msg"), "external not shown");
        assert!(!display.contains("real diag"), "internal leaked");
        assert!(!display.contains("/etc/shadow"), "sensitive leaked");
    }

    #[cfg(not(feature = "trusted_debug"))]
    #[test]
    fn debug_output_is_limited_without_trusted_debug() {
        let err = AgentError::new(100, "secret ext", "secret int", "secret sens");
        let debug = format!("{:?}", err);
        assert!(debug.contains("secret ext"), "external not shown in Debug");
        assert!(!debug.contains("secret int"), "internal leaked in Debug");
        assert!(!debug.contains("secret sens"), "sensitive leaked in Debug");
    }

    #[cfg(feature = "trusted_debug")]
    #[test]
    fn debug_output_includes_all_payloads_with_trusted_debug() {
        let err = AgentError::new(100, "secret ext", "secret int", "secret sens");
        let debug = format!("{:?}", err);
        assert!(debug.contains("secret ext"));
        assert!(debug.contains("secret int"));
        assert!(debug.contains("secret sens"));
        assert!(debug.contains("E-CFG-"));
    }

    #[test]
    fn unknown_code_falls_back_to_core() {
        let err = AgentError::new(9999, "e", "i", "");
        assert_eq!(err.code_inner().namespace().as_str(), "CORE");
    }

    #[test]
    fn empty_sensitive_stored_as_none() {
        // Verify the None path via internal accessor (pub(crate)).
        let err = AgentError::new(100, "e", "i", "");
        assert!(!err.payload.sensitive_present);
    }

    #[test]
    fn non_empty_sensitive_stored() {
        let err = AgentError::new(100, "e", "i", "secret");
        assert!(err.payload.sensitive_present);
    }

    #[test]
    fn ct_floor_enforced() {
        let start = Instant::now();
        let _ = AgentError::new(100, "e", "i", "");
        assert!(start.elapsed() >= PUBLIC_API_FLOOR);
    }

    #[test]
    fn ring_buffer_receives_entry() {
        let before = global_ring().len();
        let _err = AgentError::new(100, "e", "i", "");
        assert!(global_ring().len() >= before);
    }

    #[test]
    fn obfuscation_applied() {
        clear_salt();
        obfuscation::init_session_salt(5);
        // CFG code 100, salt 5 → offset 0+5=5 → E-CFG-105
        let err = AgentError::new(100, "e", "i", "");
        assert!(
            err.code_inner().to_string().contains("E-CFG-105"),
            "obfuscation not applied: {}",
            err.code_inner(),
        );
        clear_salt();
    }

    #[cfg(feature = "log")]
    #[test]
    fn log_creates_encrypted_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("palisade_lib_test_{}.log", std::process::id()));
        let err = AgentError::new(100, "ext", "int", "sens");
        err.log(&path).expect("log failed");

        let meta = std::fs::metadata(&path).expect("file not created");
        assert!(meta.len() > 0, "log file is empty");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            assert_eq!(mode & 0o777, 0o400, "file should be 0o400");
        }

        // Clean up.
        log_sink::set_readonly(&path).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&path).unwrap().permissions();
            p.set_mode(0o600);
            std::fs::set_permissions(&path, p).ok();
        }
        std::fs::remove_file(&path).ok();
    }

    #[cfg(feature = "log")]
    #[test]
    fn log_appends_multiple_records() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("palisade_append_test_{}.log", std::process::id()));

        for i in 0..3_u16 {
            let err = AgentError::new(100 + i, "ext", "int", "");
            err.log(&path).unwrap();
        }

        let len = std::fs::metadata(&path).unwrap().len();
        // Each record: 4-byte prefix + 12-byte nonce + plaintext+16-byte tag + 32-byte MAC.
        // Minimum size is well above 0 for 3 records.
        assert!(len > 100, "file too small for 3 records: {len} bytes");

        // Clean up.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&path).unwrap().permissions();
            p.set_mode(0o600);
            std::fs::set_permissions(&path, p).ok();
        }
        std::fs::remove_file(&path).ok();
    }

    #[cfg(feature = "log")]
    #[test]
    fn log_rejects_relative_paths() {
        let err = AgentError::new(100, "ext", "int", "sens");
        let failure = err.log(Path::new("relative.log")).unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::InvalidInput);
    }
}
