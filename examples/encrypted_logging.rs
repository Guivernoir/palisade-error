use palisade_errors::AgentError;
use std::error::Error;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let path = temp_log_path();
    let err = AgentError::new(
        611,
        "Audit operation failed",
        "encrypted append-only log write failed after permission change",
        "/var/log/palisade/forensics.log",
    );

    err.log(&path)?;
    println!("wrote encrypted record to {}", path.display());

    cleanup_log(&path);
    Ok(())
}

fn temp_log_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "palisade_errors_example_{}_{}.log",
        std::process::id(),
        "encrypted"
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
