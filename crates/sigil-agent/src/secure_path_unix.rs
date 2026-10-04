use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail};

pub(super) fn ensure_protected_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !path.parent().is_some_and(|parent| parent.is_dir()) {
                bail!(
                    "refusing to create {} because its parent directory is missing",
                    path.display()
                );
            }
            match fs::create_dir(path) {
                Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                    .with_context(|| {
                        format!("could not set protected permissions on {}", path.display())
                    })?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("could not create protected directory {}", path.display())
                    });
                }
            }
            validate_directory(path)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "refusing to trust Sigil directory {} because it could not be inspected; recreate it as root-owned mode 0755",
                path.display()
            )
        }),
    }
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    let fix = format!(
        "delete {} and let sigil-agent recreate it, or set it to root-owned mode 0755",
        path.display()
    );
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "refusing unsafe Sigil directory {}: it is a symlink or not a directory; {fix}",
            path.display()
        );
    }
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!(
            "refusing unsafe Sigil directory {}: it must be owned by root and not group/world writable; {fix}",
            path.display()
        );
    }
    Ok(())
}
