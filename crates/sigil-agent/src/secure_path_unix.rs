use std::{
    fs,
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail};

use crate::secure_path::ProtectedFileMode;

pub(super) fn open_protected_file(path: &Path, mode: ProtectedFileMode) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    match mode {
        ProtectedFileMode::Read => {
            options.read(true);
        }
        ProtectedFileMode::Append => {
            options.create(true).append(true);
        }
        ProtectedFileMode::Truncate => {
            options.create(true).write(true).truncate(true);
        }
        ProtectedFileMode::CreateNew => {
            options.create_new(true).write(true);
        }
    }
    let file = options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("could not safely open {}", path.display()))?;
    validate_open_file(&file, path)?;
    Ok(file)
}

fn validate_open_file(file: &fs::File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "refusing protected file {} because it is not a regular file",
            path.display()
        );
    }
    if metadata.nlink() > 1 {
        bail!(
            "refusing protected file {} because it has {} hard links",
            path.display(),
            metadata.nlink()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "refusing protected file {} because it is group or world writable",
            path.display()
        );
    }
    Ok(())
}

pub(super) fn replace_protected_file(source: &Path, destination: &Path) -> Result<()> {
    let source_file = open_protected_file(source, ProtectedFileMode::Read)?;
    validate_open_file(&source_file, source)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            let destination_file = open_protected_file(destination, ProtectedFileMode::Read)?;
            validate_open_file(&destination_file, destination)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("could not safely inspect {}", destination.display()));
        }
    }
    fs::rename(source, destination)
        .with_context(|| format!("could not replace protected file {}", destination.display()))?;
    if let Some(parent) = destination.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("could not sync protected directory {}", parent.display()))?;
    }
    Ok(())
}

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
