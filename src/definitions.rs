//! Pre-defined error codes.
//!
//! All items here are `pub(crate)`.  They are accessed externally only through
//! the numeric lookup in `lib.rs::resolve_code()`, which maps caller-supplied
//! `u16` values to `&'static ErrorCode` references.
//!
//! # Numeric ranges
//!
//! | Range     | Namespace | Domain                |
//! |-----------|-----------|-----------------------|
//! | 1 – 30    | CORE      | Fundamental system    |
//! | 100 – 131 | CFG       | Configuration         |
//! | 200 – 237 | DCP       | Deception subsystem   |
//! | 300 – 333 | TEL       | Telemetry             |
//! | 400 – 434 | COR       | Correlation/analysis  |
//! | 500 – 533 | RSP       | Response/action       |
//! | 600 – 630 | LOG       | Logging/audit         |
//! | 700 – 730 | PLT       | Platform/OS           |
//! | 800 – 830 | IO        | Filesystem/network    |
//!
//! # Impact scoring legend
//!
//! | Range      | Level      | Meaning                                  |
//! |------------|------------|------------------------------------------|
//! | 0 – 50     | Noise      | Internal noise, no operational impact    |
//! | 51 – 150   | Flaw       | Minor visual discrepancy                 |
//! | 151 – 300  | Jitter     | Performance issues                       |
//! | 301 – 450  | Glitch     | Functional error                         |
//! | 451 – 600  | Suspicion  | Logic inconsistency                      |
//! | 601 – 750  | Leak       | Information disclosure                   |
//! | 751 – 850  | Collapse   | Total emulation failure                  |
//! | 851 – 950  | Escalation | Unintended access                        |
//! | 951 – 1000 | Breach     | Sandbox breakout risk                    |

use crate::codes::namespaces;
use crate::convenience::{define_error_code, define_error_codes};
use crate::models::OperationCategory;

// ── CORE (1-30) ── Fundamental system health ──────────────────────────────────

define_error_codes! {
    &namespaces::CORE, OperationCategory::System => {
        CORE_INIT_FAILED              = (1,  600),
        CORE_SHUTDOWN_FAILED          = (2,  600),
        CORE_PANIC_RECOVERY           = (3,  700),
        CORE_INVALID_STATE            = (4,  600),
        CORE_MEMORY_ALLOC_FAILED      = (5,  700),
        CORE_THREAD_SPAWN_FAILED      = (6,  600),
        CORE_MUTEX_LOCK_FAILED        = (7,  600),
        CORE_SIGNAL_HANDLER_FAILED    = (8,  600),
        CORE_MODULE_LOAD_FAILED       = (9,  600),
        CORE_DEPENDENCY_MISSING       = (10, 600),
        CORE_VERSION_CHECK_FAILED     = (11, 600),
        CORE_RESOURCE_INIT_FAILED     = (12, 600),
        CORE_EVENT_LOOP_FAILED        = (13, 600),
        CORE_CONFIG_BOOTSTRAP_FAILED  = (14, 600),
        CORE_DATABASE_CONNECT_FAILED  = (15, 600),
        CORE_CACHE_INIT_FAILED        = (16, 600),
        CORE_QUEUE_OVERFLOW           = (17, 600),
        CORE_TIMER_SETUP_FAILED       = (18, 600),
        CORE_HOOK_REGISTRATION_FAILED = (19, 600),
        CORE_PLUGIN_INIT_FAILED       = (20, 600),
        CORE_STATE_TRANSITION_FAILED  = (21, 600),
        CORE_HEALTH_CHECK_FAILED      = (22, 600),
        CORE_BACKUP_FAILED            = (23, 600),
        CORE_RESTORE_FAILED           = (24, 600),
        CORE_MIGRATION_FAILED         = (25, 600),
        CORE_LICENSE_VALIDATION_FAILED= (26, 600),
        CORE_AUTH_INIT_FAILED         = (27, 600),
        CORE_CRYPTO_SETUP_FAILED      = (28, 600),
        CORE_NETWORK_INIT_FAILED      = (29, 600),
        CORE_API_SERVER_START_FAILED  = (30, 600),
    }
}

// ── CFG (100-131) ── Configuration & validation ───────────────────────────────

define_error_codes! {
    &namespaces::CFG, OperationCategory::Configuration => {
        CFG_PARSE_FAILED              = (100, 200),
        CFG_VALIDATION_FAILED         = (101, 200),
        CFG_MISSING_REQUIRED          = (102, 200),
        CFG_INVALID_VALUE             = (103, 200),
        CFG_INVALID_FORMAT            = (104, 200),
        CFG_PERMISSION_DENIED         = (105, 200),
        CFG_VERSION_MISMATCH          = (106, 200),
        CFG_SECURITY_VIOLATION        = (107, 200),
        CFG_LOAD_FAILED               = (108, 200),
        CFG_SAVE_FAILED               = (109, 200),
        CFG_ENV_VAR_MISSING           = (110, 200),
        CFG_TYPE_MISMATCH             = (111, 200),
        CFG_DUPLICATE_KEY             = (112, 200),
        CFG_SCHEMA_VALIDATION_FAILED  = (113, 200),
        CFG_MERGE_CONFLICT            = (114, 200),
        CFG_REMOTE_FETCH_FAILED       = (115, 200),
        CFG_LOCAL_STORE_FAILED        = (116, 200),
        CFG_ENCRYPTION_FAILED         = (117, 200),
        CFG_DECRYPTION_FAILED         = (118, 200),
        CFG_KEY_NOT_FOUND             = (119, 200),
        CFG_INVALID_PATH              = (120, 200),
        CFG_CONVERSION_FAILED         = (121, 200),
        CFG_DEFAULTS_LOAD_FAILED      = (122, 200),
        CFG_OVERRIDE_FAILED           = (123, 200),
        CFG_WATCHER_INIT_FAILED       = (124, 200),
        CFG_RELOAD_FAILED             = (125, 200),
        CFG_BACKUP_FAILED             = (126, 200),
        CFG_ROLLBACK_FAILED           = (127, 200),
        CFG_TEMPLATE_RENDER_FAILED    = (128, 200),
        CFG_VARIABLE_RESOLUTION_FAILED= (129, 200),
        CFG_SECRETS_MANAGER_FAILED    = (130, 200),
        CFG_PROFILE_SWITCH_FAILED     = (131, 200),
    }
}

// ── DCP (200-230) ── Deception infrastructure (the "stage") ──────────────────

define_error_codes! {
    &namespaces::DCP, OperationCategory::Deployment => {
        DCP_DEPLOY_FAILED               = (200, 300),
        DCP_ARTIFACT_CREATE             = (201, 300),
        DCP_ARTIFACT_WRITE              = (202, 300),
        DCP_CLEANUP_FAILED              = (203, 300),
        DCP_TAG_GENERATION              = (204, 300),
        DCP_TRIGGER_FAILED              = (205, 300),
        DCP_SIMULATION_FAILED           = (206, 300),
        DCP_BAIT_DEPLOY_FAILED          = (207, 300),
        DCP_HONEYPOT_INIT_FAILED        = (208, 300),
        DCP_FAKE_DATA_GENERATION_FAILED = (209, 300),
        DCP_REDIRECT_SETUP_FAILED       = (210, 300),
        DCP_MIMICRY_FAILED              = (211, 300),
        DCP_TARPIT_ENGAGE_FAILED        = (212, 300),
        DCP_DECOY_LAUNCH_FAILED         = (213, 300),
        DCP_SHADOW_SYSTEM_FAILED        = (214, 300),
        DCP_FINGERPRINT_MISMATCH        = (215, 300),
        DCP_BEHAVIOR_MODEL_LOAD_FAILED  = (216, 300),
        DCP_INTRUSION_SIM_FAILED        = (217, 300),
        DCP_COUNTERMEASURE_FAILED       = (218, 300),
        DCP_ARTIFACT_EXPIRATION         = (219, 300),
        DCP_DEPLOYMENT_ROLLBACK_FAILED  = (220, 300),
        DCP_RESOURCE_ALLOCATION_FAILED  = (221, 300),
        DCP_TEMPLATE_LOAD_FAILED        = (222, 300),
        DCP_VALIDATION_CHECK_FAILED     = (223, 300),
        DCP_INTEGRITY_CHECK_FAILED      = (224, 300),
        DCP_NETWORK_SIM_FAILED          = (225, 300),
        DCP_ACCESS_CONTROL_FAILED       = (226, 300),
        DCP_ENCRYPTED_ARTIFACT_FAILED   = (227, 300),
        DCP_DECRYPT_ARTIFACT_FAILED     = (228, 300),
        DCP_DYNAMIC_GENERATION_FAILED   = (229, 300),
        DCP_PERSISTENCE_FAILED          = (230, 300),
    }
}

// ── DCP (231-237) ── Deception narrative failures (the "script") ─────────────

define_error_codes! {
    &namespaces::DCP, OperationCategory::Deception => {
        DCP_NARRATIVE_DESYNC      = (231, 500),
        DCP_NARRATIVE_BREAK       = (232, 800),
        DCP_BELIEVABILITY_LOW     = (233, 500),
        DCP_ADVERSARY_ADAPTATION  = (234, 800),
        DCP_STATE_VIOLATION       = (235, 500),
        DCP_TEMPORAL_INCONSISTENCY= (236, 500),
        DCP_CAUSALITY_BREACH      = (237, 500),
    }
}

// ── TEL (300-333) ── Telemetry & observability ────────────────────────────────

define_error_codes! {
    &namespaces::TEL, OperationCategory::Monitoring => {
        TEL_INIT_FAILED               = (300, 400),
        TEL_WATCH_FAILED              = (301, 400),
        TEL_EVENT_LOST                = (302, 400),
        TEL_CHANNEL_CLOSED            = (303, 400),
        TEL_MONITOR_CRASH             = (304, 400),
        TEL_METRIC_COLLECTION_FAILED  = (305, 400),
        TEL_EXPORT_FAILED             = (306, 400),
        TEL_AGGREGATION_FAILED        = (307, 400),
        TEL_TRACE_SPAN_FAILED         = (308, 400),
        TEL_REMOTE_SEND_FAILED        = (309, 400),
        TEL_BUFFER_OVERFLOW           = (310, 400),
        TEL_INVALID_METRIC            = (311, 400),
        TEL_SAMPLING_FAILED           = (312, 400),
        TEL_PROPAGATION_FAILED        = (313, 400),
        TEL_ENDPOINT_UNREACHABLE      = (314, 400),
        TEL_AUTH_FAILED               = (315, 400),
        TEL_COMPRESSION_FAILED        = (316, 400),
        TEL_DECOMPRESSION_FAILED      = (317, 400),
        TEL_FILTER_APPLY_FAILED       = (318, 400),
        TEL_ALERT_TRIGGER_FAILED      = (319, 400),
        TEL_DASHBOARD_UPDATE_FAILED   = (320, 400),
        TEL_LOG_INGEST_FAILED         = (321, 400),
        TEL_QUERY_FAILED              = (322, 400),
        TEL_RETENTION_POLICY_FAILED   = (323, 400),
        TEL_BACKPRESSURE              = (324, 400),
        TEL_INSTRUMENTATION_FAILED    = (325, 400),
        TEL_BATCH_PROCESS_FAILED      = (326, 400),
        TEL_SERIALIZATION_FAILED      = (327, 400),
        TEL_DESERIALIZATION_FAILED    = (328, 400),
        TEL_RESOURCE_MONITOR_FAILED   = (329, 400),
        TEL_HEARTBEAT_FAILED          = (330, 400),
        TEL_EVASION_DETECTED          = (331, 800),
        TEL_SENSOR_BYPASS             = (332, 700),
        TEL_OBSERVABILITY_GAP         = (333, 700),
    }
}

// ── COR (400-434) ── Correlation & analysis ───────────────────────────────────

define_error_codes! {
    &namespaces::COR, OperationCategory::Analysis => {
        COR_RULE_EVAL_FAILED              = (400, 300),
        COR_BUFFER_OVERFLOW               = (401, 300),
        COR_INVALID_SCORE                 = (402, 300),
        COR_WINDOW_EXPIRED                = (403, 300),
        COR_INVALID_ARTIFACT              = (404, 300),
        COR_PATTERN_MATCH_FAILED          = (405, 300),
        COR_DATA_INGEST_FAILED            = (406, 300),
        COR_AGGREGATION_FAILED            = (407, 300),
        COR_THRESHOLD_BREACH              = (408, 300),
        COR_FALSE_POSITIVE                = (409, 300),
        COR_EVENT_MERGE_FAILED            = (410, 300),
        COR_CONTEXT_LOAD_FAILED           = (411, 300),
        COR_ANOMALY_DETECT_FAILED         = (412, 300),
        COR_MODEL_TRAIN_FAILED            = (413, 300),
        COR_INFERENCE_FAILED              = (414, 300),
        COR_DATA_NORMALIZATION_FAILED     = (415, 300),
        COR_FEATURE_EXTRACTION_FAILED     = (416, 300),
        COR_CLUSTERING_FAILED             = (417, 300),
        COR_OUTLIER_DETECTION_FAILED      = (418, 300),
        COR_TIME_SERIES_ANALYSIS_FAILED   = (419, 300),
        COR_GRAPH_BUILD_FAILED            = (420, 300),
        COR_PATH_ANALYSIS_FAILED          = (421, 300),
        COR_RULE_UPDATE_FAILED            = (422, 300),
        COR_VALIDATION_FAILED             = (423, 300),
        COR_EXPORT_FAILED                 = (424, 300),
        COR_IMPORT_FAILED                 = (425, 300),
        COR_QUERY_EXEC_FAILED             = (426, 300),
        COR_INDEX_BUILD_FAILED            = (427, 300),
        COR_SEARCH_FAILED                 = (428, 300),
        COR_ENRICHMENT_FAILED             = (429, 300),
        COR_DEDUPLICATION_FAILED          = (430, 300),
        COR_CONFIDENCE_DEGRADATION        = (431, 300),
        COR_MODEL_DRIFT                   = (432, 300),
        COR_HYPOTHESIS_INVALIDATED        = (433, 550),
        COR_ACTOR_CONFLICT                = (434, 300),
    }
}

// ── RSP (500-533) ── Response & action ───────────────────────────────────────

define_error_codes! {
    &namespaces::RSP, OperationCategory::Response => {
        RSP_EXEC_FAILED               = (500, 300),
        RSP_TIMEOUT                   = (501, 300),
        RSP_INVALID_ACTION            = (502, 300),
        RSP_RATE_LIMITED              = (503, 300),
        RSP_HANDLER_NOT_FOUND         = (504, 300),
        RSP_SERIALIZATION_FAILED      = (505, 300),
        RSP_DESERIALIZATION_FAILED    = (506, 300),
        RSP_VALIDATION_FAILED         = (507, 300),
        RSP_AUTH_FAILED               = (508, 300),
        RSP_PERMISSION_DENIED         = (509, 300),
        RSP_RESOURCE_NOT_FOUND        = (510, 300),
        RSP_CONFLICT                  = (511, 300),
        RSP_INTERNAL_ERROR            = (512, 300),
        RSP_BAD_REQUEST               = (513, 300),
        RSP_UNAVAILABLE               = (514, 300),
        RSP_GATEWAY_TIMEOUT           = (515, 300),
        RSP_TOO_MANY_REQUESTS         = (516, 300),
        RSP_PAYLOAD_TOO_LARGE         = (517, 300),
        RSP_UNSUPPORTED_MEDIA         = (518, 300),
        RSP_METHOD_NOT_ALLOWED        = (519, 300),
        RSP_NOT_ACCEPTABLE            = (520, 300),
        RSP_PROXY_AUTH_REQUIRED       = (521, 300),
        RSP_REQUEST_TIMEOUT           = (522, 300),
        RSP_PRECONDITION_FAILED       = (523, 300),
        RSP_EXPECTATION_FAILED        = (524, 300),
        RSP_MISDIRECTED_REQUEST       = (525, 300),
        RSP_UNPROCESSABLE_ENTITY      = (526, 300),
        RSP_LOCKED                    = (527, 300),
        RSP_FAILED_DEPENDENCY         = (528, 300),
        RSP_UPGRADE_REQUIRED          = (529, 300),
        RSP_PRECONDITION_REQUIRED     = (530, 300),
        RSP_TIMING_ANOMALY            = (531, 500),
        RSP_ENTROPY_LOW               = (532, 500),
        RSP_BEHAVIORAL_INCONSISTENCY  = (533, 500),
    }
}

// ── LOG (600-630) ── Audit & logging ─────────────────────────────────────────

define_error_codes! {
    &namespaces::LOG, OperationCategory::Audit => {
        LOG_WRITE_FAILED              = (600, 200),
        LOG_ROTATE_FAILED             = (601, 200),
        LOG_BUFFER_FULL               = (602, 200),
        LOG_SERIALIZATION             = (603, 200),
        LOG_INIT_FAILED               = (604, 200),
        LOG_FLUSH_FAILED              = (605, 200),
        LOG_LEVEL_INVALID             = (606, 200),
        LOG_FILTER_APPLY_FAILED       = (607, 200),
        LOG_APPENDER_FAILED           = (608, 200),
        LOG_REMOTE_SEND_FAILED        = (609, 200),
        LOG_COMPRESSION_FAILED        = (610, 200),
        LOG_ENCRYPTION_FAILED         = (611, 200),
        LOG_ARCHIVE_FAILED            = (612, 200),
        LOG_PURGE_FAILED              = (613, 200),
        LOG_INDEX_FAILED              = (614, 200),
        LOG_SEARCH_FAILED             = (615, 200),
        LOG_PARSE_FAILED              = (616, 200),
        LOG_FORMAT_INVALID            = (617, 200),
        LOG_TIMESTAMP_FAILED          = (618, 200),
        LOG_METADATA_MISSING          = (619, 200),
        LOG_ROLLOVER_FAILED           = (620, 200),
        LOG_BACKUP_FAILED             = (621, 200),
        LOG_RESTORE_FAILED            = (622, 200),
        LOG_QUEUE_OVERFLOW            = (623, 200),
        LOG_ASYNC_SEND_FAILED         = (624, 200),
        LOG_SYNC_FAILED               = (625, 200),
        LOG_HANDLER_CRASH             = (626, 200),
        LOG_CONFIG_LOAD_FAILED        = (627, 200),
        LOG_RELOAD_FAILED             = (628, 200),
        LOG_EXPORT_FAILED             = (629, 200),
        LOG_IMPORT_FAILED             = (630, 200),
    }
}

// ── PLT (700-730) ── Platform & OS ────────────────────────────────────────────

define_error_codes! {
    &namespaces::PLT, OperationCategory::System => {
        PLT_UNSUPPORTED                  = (700, 400),
        PLT_SYSCALL_FAILED               = (701, 400),
        PLT_PERMISSION_DENIED            = (702, 400),
        PLT_RESOURCE_EXHAUSTED           = (703, 400),
        PLT_OS_VERSION_MISMATCH          = (704, 400),
        PLT_HARDWARE_UNSUPPORTED         = (705, 400),
        PLT_DRIVER_LOAD_FAILED           = (706, 400),
        PLT_API_CALL_FAILED              = (707, 400),
        PLT_ENV_DETECT_FAILED            = (708, 400),
        PLT_VIRTUALIZATION_FAILED        = (709, 400),
        PLT_CONTAINER_INIT_FAILED        = (710, 400),
        PLT_KERNEL_MODULE_FAILED         = (711, 400),
        PLT_FILESYSTEM_MOUNT_FAILED      = (712, 400),
        PLT_NETWORK_INTERFACE_FAILED     = (713, 400),
        PLT_PROCESS_SPAWN_FAILED         = (714, 400),
        PLT_SIGNAL_SEND_FAILED           = (715, 400),
        PLT_MEMORY_MAP_FAILED            = (716, 400),
        PLT_THREAD_AFFINITY_FAILED       = (717, 400),
        PLT_POWER_MANAGEMENT_FAILED      = (718, 400),
        PLT_BOOTSTRAP_FAILED             = (719, 400),
        PLT_SHUTDOWN_HOOK_FAILED         = (720, 400),
        PLT_COMPATIBILITY_CHECK_FAILED   = (721, 400),
        PLT_LIBRARY_LOAD_FAILED          = (722, 400),
        PLT_SYMBOL_RESOLVE_FAILED        = (723, 400),
        PLT_SECURITY_POLICY_FAILED       = (724, 400),
        PLT_AUDIT_HOOK_FAILED            = (725, 400),
        PLT_RESOURCE_LIMIT_REACHED       = (726, 400),
        PLT_CLOCK_SYNC_FAILED            = (727, 400),
        PLT_DEVICE_ACCESS_FAILED         = (728, 400),
        PLT_FIRMWARE_UPDATE_FAILED       = (729, 400),
        PLT_BIOS_CONFIG_FAILED           = (730, 400),
    }
}

// ── IO (800-830) ── Filesystem & networking ───────────────────────────────────

define_error_codes! {
    &namespaces::IO, OperationCategory::IO => {
        IO_READ_FAILED                = (800, 200),
        IO_WRITE_FAILED               = (801, 200),
        IO_NETWORK_ERROR              = (802, 200),
        IO_TIMEOUT                    = (803, 200),
        IO_NOT_FOUND                  = (804, 200),
        IO_METADATA_FAILED            = (805, 200),
        IO_OPEN_FAILED                = (806, 200),
        IO_CLOSE_FAILED               = (807, 200),
        IO_SEEK_FAILED                = (808, 200),
        IO_FLUSH_FAILED               = (809, 200),
        IO_PERMISSION_DENIED          = (810, 200),
        IO_INTERRUPTED                = (811, 200),
        IO_WOULD_BLOCK                = (812, 200),
        IO_INVALID_INPUT              = (813, 200),
        IO_BROKEN_PIPE                = (814, 200),
        IO_CONNECTION_RESET           = (815, 200),
        IO_CONNECTION_REFUSED         = (816, 200),
        IO_NOT_CONNECTED              = (817, 200),
        IO_ADDR_IN_USE                = (818, 200),
        IO_ADDR_NOT_AVAILABLE         = (819, 200),
        IO_NETWORK_DOWN               = (820, 200),
        IO_NETWORK_UNREACHABLE        = (821, 200),
        IO_HOST_UNREACHABLE           = (822, 200),
        IO_ALREADY_EXISTS             = (823, 200),
        IO_IS_DIRECTORY               = (824, 200),
        IO_NOT_DIRECTORY              = (825, 200),
        IO_DIRECTORY_NOT_EMPTY        = (826, 200),
        IO_READ_ONLY_FS               = (827, 200),
        IO_FS_QUOTA_EXCEEDED          = (828, 200),
        IO_STALE_NFS_HANDLE           = (829, 200),
        IO_REMOTE_IO                  = (830, 200),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::ErrorImpact;

    #[test]
    fn core_codes_in_range() {
        assert!(CORE_INIT_FAILED.code() >= 1 && CORE_INIT_FAILED.code() <= 99);
        assert!(CORE_API_SERVER_START_FAILED.code() <= 99);
    }

    #[test]
    fn cfg_codes_in_range() {
        assert!(CFG_PARSE_FAILED.code() >= 100 && CFG_PARSE_FAILED.code() <= 199);
        assert!(CFG_PROFILE_SWITCH_FAILED.code() <= 199);
    }

    #[test]
    fn io_codes_in_range() {
        assert!(IO_READ_FAILED.code() >= 800 && IO_READ_FAILED.code() <= 899);
        assert!(IO_REMOTE_IO.code() <= 899);
    }

    #[test]
    fn critical_impact_mappings() {
        assert_eq!(DCP_NARRATIVE_BREAK.impact_level(), ErrorImpact::Collapse);
        assert_eq!(TEL_EVASION_DETECTED.impact_level(), ErrorImpact::Collapse);
        assert_eq!(CORE_MEMORY_ALLOC_FAILED.impact_level(), ErrorImpact::Leak);
    }

    #[test]
    fn fallback_sentinel_exists() {
        // CORE_INVALID_STATE (code 4) is the lookup fallback for unknown codes.
        assert_eq!(CORE_INVALID_STATE.code(), 4);
    }
}
