use std::{
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

/// A handle to a mounted [OverlayFS]. Once this struct is dropped
/// the overlay is removed.
///
/// [`OverlayFS`]: crate::overlayfs::OverlayFS
pub struct Scope {
    // TODO: should unmount on drop
    _upperdir: tempfile::TempDir,
    _workdir: tempfile::TempDir,
}

/// A representation of an Overlay filesystem.
///
/// Not all overlay FS features are supported. Namely, you can:
/// - specify the target directory over which to overlay.
/// - add file paths relative to the target directory and respectively
///   their contents and permissions.
///
/// Once the FS is mounted, additional files cannot be added.
///
/// # Example
///
/// ```
/// use htapod::OverlayFS
///
/// fn main() -> std::io::Result<()> {
///     let ro = std::fs::Permissions::from_mode(0o444);
///     let content = b"nameserver 1.1.1.1\n";
///     let scope_guard = OverlayFS::new("/etc")?
///         .add(content, "resolv.conf", ro)?
///         .mount()?;
///
///     assert_eq!(
///         content,
///         std::fs::read("/etc/resolv.conf").unwrap().as_slice()
///     );
/// }
/// ```
///
///
pub struct OverlayFS {
    target: PathBuf,
    upperdir: tempfile::TempDir,
    workdir: tempfile::TempDir,
}

impl OverlayFS {
    /// Creates a new overlay for the target directory.
    ///
    /// The `upperdir` and `workdir` of the overlay FS are
    /// temporary directories and all files added with `add`
    /// will be written into the `upperdir`.
    pub fn new<P>(target: P) -> std::io::Result<Self>
    where
        P: AsRef<Path>,
    {
        // TODO: check if target is dir.
        Ok(Self {
            target: target.as_ref().into(),
            upperdir: tempfile::tempdir()?,
            workdir: tempfile::tempdir()?,
        })
    }

    /// Adds a file under this overlay's target directory.
    ///
    /// The file will contain `content` and will have the given `permissions`.
    pub fn add<C, P>(
        self,
        content: C,
        path_relative_to_target: P,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<Self>
    where
        C: AsRef<[u8]>,
        P: AsRef<Path>,
    {
        let temppath = self.upperdir.path().join(
            path_relative_to_target
                .as_ref()
                .strip_prefix("/")
                .unwrap_or(path_relative_to_target.as_ref()),
        );

        if let Some(dir) = temppath.parent() {
            std::fs::create_dir_all(dir)?;
        }

        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(permissions.mode())
            .open(&temppath)
            .and_then(|mut f| f.write(content.as_ref()))?;

        Ok(self)
    }

    /// Mounts and consumes the `OverlayFS`.
    ///
    /// On success, a scope guard is returned. The overlay will be unmounted
    /// when the scope guard is dropped.
    pub fn mount(self) -> std::io::Result<Scope> {
        let overlay_fs = Some(b"overlay".as_ref());
        let mount_options = [
            b"lowerdir=" as &[_],
            self.target.as_os_str().as_bytes(),
            b",upperdir=" as &[_],
            self.upperdir.path().as_os_str().as_bytes(),
            b",workdir=" as &[_],
            self.workdir.path().as_os_str().as_bytes(),
        ]
        .concat();

        nix::mount::mount(
            overlay_fs,
            &self.target,
            overlay_fs,
            nix::mount::MsFlags::empty(),
            Some(mount_options.as_slice()),
        )?;

        Ok(Scope {
            _upperdir: self.upperdir,
            _workdir: self.workdir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_overlayfs() {
        // Requires sudo
        let tempdir = tempfile::tempdir().unwrap();
        let content1 = b"hello";
        let content2 = b"hello";
        let ro = std::fs::Permissions::from_mode(0o444);

        let _fs_scope = OverlayFS::new(tempdir.path())
            .and_then(|fs| fs.add(content1, "file1", ro.clone()))
            .and_then(|fs| fs.add(content2, "file2", ro))
            .and_then(|fs| fs.mount())
            .unwrap();

        assert_eq!(
            content1,
            std::fs::read(tempdir.path().join("file1"))
                .unwrap()
                .as_slice()
        );
        assert_eq!(
            content2,
            std::fs::read(tempdir.path().join("file2"))
                .unwrap()
                .as_slice()
        );
    }
}
