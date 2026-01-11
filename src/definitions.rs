//! Pre-defined error codes for the deception agent.
//!
//! Each code includes:
//! - Unique identifier (E-XXX-YYY)
//! - Operation category (for external context)
//! - Implicit namespace (for internal tracking)
//!
//! Error codes are organized into namespaces with reserved numeric ranges
//! to prevent collisions and enable future expansion.
//!
//! # Available Error Codes
//!
//! - **CORE** (001-099): Core system errors
//! - **CFG** (100-199): Configuration errors
//! - **DCP** (200-299): Deception subsystem errors
//! - **TEL** (300-399): Telemetry errors
//! - **COR** (400-499): Correlation errors
//! - **RSP** (500-599): Response errors
//! - **LOG** (600-699): Logging errors
//! - **PLT** (700-799): Platform errors
//! - **IO** (800-899): I/O errors

use crate::{ErrorCode, OperationCategory};

/// Error code range constants for maintaining namespace boundaries.
pub mod ranges {
    /// Core system errors: 001-099
    pub const CORE_START: u16 = 1;
    pub const CORE_END: u16 = 99;
    
    /// Configuration errors: 100-199
    pub const CFG_START: u16 = 100;
    pub const CFG_END: u16 = 199;
    
    /// Deception subsystem errors: 200-299
    pub const DCP_START: u16 = 200;
    pub const DCP_END: u16 = 299;
    
    /// Telemetry errors: 300-399
    pub const TEL_START: u16 = 300;
    pub const TEL_END: u16 = 399;
    
    /// Correlation errors: 400-499
    pub const COR_START: u16 = 400;
    pub const COR_END: u16 = 499;
    
    /// Response errors: 500-599
    pub const RSP_START: u16 = 500;
    pub const RSP_END: u16 = 599;
    
    /// Logging errors: 600-699
    pub const LOG_START: u16 = 600;
    pub const LOG_END: u16 = 699;
    
    /// Platform errors: 700-799
    pub const PLT_START: u16 = 700;
    pub const PLT_END: u16 = 799;
    
    /// I/O errors: 800-899
    pub const IO_START: u16 = 800;
    pub const IO_END: u16 = 899;
}

// Core System Errors (001-099)
pub const CORE_INIT_FAILED: ErrorCode = ErrorCode::new("CORE", 1, OperationCategory::System);
pub const CORE_SHUTDOWN_FAILED: ErrorCode = ErrorCode::new("CORE", 2, OperationCategory::System);
pub const CORE_PANIC_RECOVERY: ErrorCode = ErrorCode::new("CORE", 3, OperationCategory::System);
pub const CORE_INVALID_STATE: ErrorCode = ErrorCode::new("CORE", 4, OperationCategory::System);

// Configuration Errors (100-199)
pub const CFG_PARSE_FAILED: ErrorCode = ErrorCode::new("CFG", 100, OperationCategory::Configuration);
pub const CFG_VALIDATION_FAILED: ErrorCode = ErrorCode::new("CFG", 101, OperationCategory::Configuration);
pub const CFG_MISSING_REQUIRED: ErrorCode = ErrorCode::new("CFG", 102, OperationCategory::Configuration);
pub const CFG_INVALID_VALUE: ErrorCode = ErrorCode::new("CFG", 103, OperationCategory::Configuration);
pub const CFG_INVALID_FORMAT: ErrorCode = ErrorCode::new("CFG", 104, OperationCategory::Configuration);
pub const CFG_PERMISSION_DENIED: ErrorCode = ErrorCode::new("CFG", 105, OperationCategory::Configuration);
pub const CFG_VERSION_MISMATCH: ErrorCode = ErrorCode::new("CFG", 106, OperationCategory::Configuration);
pub const CFG_SECURITY_VIOLATION: ErrorCode = ErrorCode::new("CFG", 107, OperationCategory::Configuration);

// Deception Subsystem Errors (200-299)
pub const DCP_DEPLOY_FAILED: ErrorCode = ErrorCode::new("DCP", 200, OperationCategory::Deployment);
pub const DCP_ARTIFACT_CREATE: ErrorCode = ErrorCode::new("DCP", 201, OperationCategory::Deployment);
pub const DCP_ARTIFACT_WRITE: ErrorCode = ErrorCode::new("DCP", 202, OperationCategory::Deployment);
pub const DCP_CLEANUP_FAILED: ErrorCode = ErrorCode::new("DCP", 203, OperationCategory::Deployment);
pub const DCP_TAG_GENERATION: ErrorCode = ErrorCode::new("DCP", 204, OperationCategory::Deployment);

// Telemetry Errors (300-399)
pub const TEL_INIT_FAILED: ErrorCode = ErrorCode::new("TEL", 300, OperationCategory::Monitoring);
pub const TEL_WATCH_FAILED: ErrorCode = ErrorCode::new("TEL", 301, OperationCategory::Monitoring);
pub const TEL_EVENT_LOST: ErrorCode = ErrorCode::new("TEL", 302, OperationCategory::Monitoring);
pub const TEL_CHANNEL_CLOSED: ErrorCode = ErrorCode::new("TEL", 303, OperationCategory::Monitoring);
pub const TEL_MONITOR_CRASH: ErrorCode = ErrorCode::new("TEL", 304, OperationCategory::Monitoring);

// Correlation Errors (400-499)
pub const COR_RULE_EVAL_FAILED: ErrorCode = ErrorCode::new("COR", 400, OperationCategory::Analysis);
pub const COR_BUFFER_OVERFLOW: ErrorCode = ErrorCode::new("COR", 401, OperationCategory::Analysis);
pub const COR_INVALID_SCORE: ErrorCode = ErrorCode::new("COR", 402, OperationCategory::Analysis);
pub const COR_WINDOW_EXPIRED: ErrorCode = ErrorCode::new("COR", 403, OperationCategory::Analysis);
pub const COR_INVALID_ARTIFACT: ErrorCode = ErrorCode::new("COR", 404, OperationCategory::Analysis);

// Response Errors (500-599)
pub const RSP_EXEC_FAILED: ErrorCode = ErrorCode::new("RSP", 500, OperationCategory::Response);
pub const RSP_TIMEOUT: ErrorCode = ErrorCode::new("RSP", 501, OperationCategory::Response);
pub const RSP_INVALID_ACTION: ErrorCode = ErrorCode::new("RSP", 502, OperationCategory::Response);
pub const RSP_RATE_LIMITED: ErrorCode = ErrorCode::new("RSP", 503, OperationCategory::Response);

// Logging Errors (600-699)
pub const LOG_WRITE_FAILED: ErrorCode = ErrorCode::new("LOG", 600, OperationCategory::Audit);
pub const LOG_ROTATE_FAILED: ErrorCode = ErrorCode::new("LOG", 601, OperationCategory::Audit);
pub const LOG_BUFFER_FULL: ErrorCode = ErrorCode::new("LOG", 602, OperationCategory::Audit);
pub const LOG_SERIALIZATION: ErrorCode = ErrorCode::new("LOG", 603, OperationCategory::Audit);

// Platform Errors (700-799)
pub const PLT_UNSUPPORTED: ErrorCode = ErrorCode::new("PLT", 700, OperationCategory::System);
pub const PLT_SYSCALL_FAILED: ErrorCode = ErrorCode::new("PLT", 701, OperationCategory::System);
pub const PLT_PERMISSION_DENIED: ErrorCode = ErrorCode::new("PLT", 702, OperationCategory::System);
pub const PLT_RESOURCE_EXHAUSTED: ErrorCode = ErrorCode::new("PLT", 703, OperationCategory::System);

// I/O Errors (800-899)
pub const IO_READ_FAILED: ErrorCode = ErrorCode::new("IO", 800, OperationCategory::IO);
pub const IO_WRITE_FAILED: ErrorCode = ErrorCode::new("IO", 801, OperationCategory::IO);
pub const IO_NETWORK_ERROR: ErrorCode = ErrorCode::new("IO", 802, OperationCategory::IO);
pub const IO_TIMEOUT: ErrorCode = ErrorCode::new("IO", 803, OperationCategory::IO);
pub const IO_NOT_FOUND: ErrorCode = ErrorCode::new("IO", 804, OperationCategory::IO);
pub const IO_METADATA_FAILED: ErrorCode = ErrorCode::new("IO", 805, OperationCategory::IO);