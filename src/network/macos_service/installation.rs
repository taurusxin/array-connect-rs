use crate::{Result, VpnError};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, c_char, c_int},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::Command,
};

const ROOT: &str = "/Library/PrivilegedHelperTools/com.taurusxin.arrayconnect.vpnd";
const PLIST: &str = "/Library/LaunchDaemons/com.taurusxin.arrayconnect.vpnd.plist";
const JOB: &str = "system/com.taurusxin.arrayconnect.vpnd";
const HELPER: &str = "array-connect-vpnd";
const RECEIPT: &str = "receipt.json";
const PLIST_DATA: &[u8] = include_bytes!("vpnd.plist");
const CDHASH_LEN: usize = 40;

unsafe extern "C" {
    fn ac_app_cdhash(hash: *mut c_char) -> bool;
    fn ac_daemon_cdhash(hash: *mut c_char) -> bool;
    fn ac_protocol_version() -> c_int;
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub client: String,
    pub daemon: String,
    pub protocol: c_int,
}

pub(super) fn protocol_version() -> c_int {
    unsafe { ac_protocol_version() }
}

pub(super) fn app_hash() -> Option<String> {
    code_hash(ac_app_cdhash)
}

pub(super) fn daemon_hash() -> Option<String> {
    code_hash(ac_daemon_cdhash)
}

fn code_hash(read: unsafe extern "C" fn(*mut c_char) -> bool) -> Option<String> {
    let mut hash = [0; CDHASH_LEN + 1];
    if !unsafe { read(hash.as_mut_ptr()) } {
        return None;
    }
    let hash = unsafe { CStr::from_ptr(hash.as_ptr()) }.to_str().ok()?;
    is_hex(hash, CDHASH_LEN).then(|| hash.to_owned())
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn trusted_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other(
            "unsafe ownership or permissions on the vpnd directory",
        ));
    }
    Ok(())
}

fn trusted_file(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other(
            "unsafe ownership or permissions on a vpnd file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("oversized vpnd file"));
    }
    Ok(bytes)
}

fn installation_root(create: bool) -> io::Result<&'static Path> {
    let root = Path::new(ROOT);
    let parent = root.parent().expect("helper directory has a parent");
    trusted_directory(Path::new("/Library"))?;
    for directory in [parent, root] {
        if create {
            match DirBuilder::new().mode(0o755).create(directory) {
                Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        trusted_directory(directory)?;
    }
    Ok(root)
}

fn active_release(root: &Path) -> io::Result<PathBuf> {
    let pointer = root.join("current");
    let metadata = fs::symlink_metadata(&pointer)?;
    if !metadata.is_symlink() || metadata.uid() != 0 {
        return Err(io::Error::other("invalid vpnd installation pointer"));
    }
    let target = fs::read_link(pointer)?;
    if !target
        .to_str()
        .and_then(|name| name.strip_prefix("build-"))
        .is_some_and(|suffix| is_hex(suffix, 16))
    {
        return Err(io::Error::other("invalid vpnd installation directory name"));
    }
    Ok(target)
}

pub(super) fn read_receipt() -> io::Result<Receipt> {
    let root = installation_root(false)?;
    let active = active_release(root)?;
    let release = root.join(active);
    trusted_directory(&release).map_err(incomplete_install)?;
    let bytes = trusted_file(&release.join(RECEIPT), 512).map_err(incomplete_install)?;
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    if !is_hex(&receipt.client, CDHASH_LEN) || !is_hex(&receipt.daemon, CDHASH_LEN) {
        return Err(io::Error::other("invalid vpnd code hash"));
    }
    Ok(receipt)
}

fn incomplete_install(error: io::Error) -> io::Error {
    io::Error::other(format!("incomplete vpnd installation: {error}"))
}

const INSTALL_DIALOG: &str = r#"
on run argv
    set commandText to "/bin/sh -c " & quoted form of (item 1 of argv) & " array-connect-install " & quoted form of (item 2 of argv) & space & quoted form of (item 3 of argv) & space & quoted form of (item 4 of argv)
    do shell script commandText with administrator privileges
end run
"#;

pub(super) fn request_install(payload: &Path, digest: &str) -> Result<()> {
    let client = app_hash()
        .ok_or_else(|| VpnError::Network("请从 macOS 应用包打开 Array Connect".into()))?;
    if !payload.is_absolute() || !payload.is_file() || !is_hex(digest, 64) {
        return Err(VpnError::Network(
            "应用包缺少有效的 array-connect-vpnd".into(),
        ));
    }
    let output = Command::new("/usr/bin/osascript")
        .env_clear()
        .current_dir("/")
        .args(["-e", INSTALL_DIALOG, include_str!("install.sh")])
        .arg(payload)
        .args([digest, &client])
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    let error = String::from_utf8_lossy(&output.stderr);
    let error = error.trim();
    if error.ends_with("(-128)") {
        return Err(VpnError::Network("已取消 VPN 网络服务安装".into()));
    }
    Err(VpnError::Network(format!(
        "无法安装 macOS VPN 网络服务：{error}"
    )))
}

/// Installs the verified executable from the one-time administrator operation.
pub fn install_daemon(client: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || !is_hex(client, CDHASH_LEN) {
        return Err(VpnError::Network(
            "vpnd installation requires administrator authorization".into(),
        ));
    }
    let daemon = daemon_hash()
        .ok_or_else(|| VpnError::Network("invalid array-connect-vpnd code signature".into()))?;
    install(Receipt {
        client: client.to_owned(),
        daemon,
        protocol: protocol_version(),
    })?;
    Ok(())
}

fn install(receipt: Receipt) -> io::Result<()> {
    let root = installation_root(true)?;
    trusted_directory(Path::new("/Library/LaunchDaemons"))?;
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join("install.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other("another vpnd installation is in progress"));
    }
    let old = match active_release(root) {
        Ok(path) => Some(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let new = PathBuf::from(format!("build-{:016x}", rand::random::<u64>()));
    let release = root.join(&new);
    DirBuilder::new().mode(0o755).create(&release)?;
    let result = (|| {
        fs::set_permissions(&release, fs::Permissions::from_mode(0o755))?;
        let helper = release.join(HELPER);
        fs::copy(std::env::current_exe()?, &helper)?;
        fs::set_permissions(helper, fs::Permissions::from_mode(0o755))?;
        let path = release.join(RECEIPT);
        let mut file = File::create_new(&path)?;
        serde_json::to_writer(&mut file, &receipt)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
        activate(root, &new, old.as_deref())
    })();
    // A failed rollback may leave the new release active. Never remove it in
    // that case. Cleanup deletes only the two files owned by this installer.
    if result.is_err() {
        if fs::read_link(root.join("current"))
            .as_deref()
            .is_ok_and(|p| p != new)
            || fs::symlink_metadata(root.join("current"))
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        {
            remove_release(&release);
        }
    } else if let Some(old) = old {
        let previous = root.join(old);
        if trusted_directory(&previous).is_ok() {
            remove_release(&previous);
        }
    }
    result
}

fn remove_release(release: &Path) {
    let _ = fs::remove_file(release.join(HELPER));
    let _ = fs::remove_file(release.join(RECEIPT));
    let _ = fs::remove_dir(release);
}

fn activate(root: &Path, new: &Path, old: Option<&Path>) -> io::Result<()> {
    let plist = Path::new(PLIST);
    let created_plist = match trusted_file(plist, 4096) {
        Ok(contents) if contents == PLIST_DATA => false,
        Ok(_) => {
            return Err(io::Error::other(
                "unexpected existing vpnd launchd configuration",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let temporary = plist.with_extension(new);
            let mut file = File::create_new(&temporary)?;
            let result = (|| {
                file.write_all(PLIST_DATA)?;
                file.set_permissions(fs::Permissions::from_mode(0o644))?;
                file.sync_all()?;
                fs::rename(&temporary, plist)
            })();
            if result.is_err() {
                let _ = fs::remove_file(temporary);
            }
            result?;
            true
        }
        Err(error) => return Err(error),
    };

    let result = switch_job(root, new, old, launchctl);
    if result.is_err() && created_plist && launchctl(&["print", JOB]).is_err() {
        if let Err(error) = fs::remove_file(plist) {
            eprintln!("could not remove failed vpnd launchd configuration: {error}");
        }
    }
    result
}

fn switch_job(
    root: &Path,
    new: &Path,
    old: Option<&Path>,
    control: impl Fn(&[&str]) -> io::Result<()>,
) -> io::Result<()> {
    let was_loaded = control(&["print", JOB]).is_ok();
    let mut switched = false;
    let result = (|| {
        if was_loaded {
            control(&["bootout", JOB])?;
        }
        switch(root, Some(new))?;
        switched = true;
        control(&["bootstrap", "system", PLIST])
    })();
    if let Err(error) = result {
        let rollback = (|| {
            if switched {
                if control(&["print", JOB]).is_ok() {
                    control(&["bootout", JOB])?;
                }
                switch(root, old)?;
            }
            if was_loaded && control(&["print", JOB]).is_err() {
                control(&["bootstrap", "system", PLIST])?;
            }
            Ok::<(), io::Error>(())
        })();
        return match rollback {
            Ok(()) => Err(error),
            Err(cause) => Err(io::Error::other(format!(
                "{error}; vpnd rollback failed: {cause}"
            ))),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn failed_registration_restores_previous_helper() {
        let root = std::env::temp_dir().join(format!(
            "array-connect-vpnd-rollback-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir(&root).unwrap();
        let old = Path::new("build-0000000000000001");
        let new = Path::new("build-0000000000000002");
        symlink(old, root.join("current")).unwrap();
        let loaded = Cell::new(true);
        let control = |args: &[&str]| match args[0] {
            "print" if loaded.get() => Ok(()),
            "print" => Err(io::Error::other("not loaded")),
            "bootout" => {
                loaded.set(false);
                Ok(())
            }
            "bootstrap" => {
                if fs::read_link(root.join("current"))? == new {
                    Err(io::Error::other("simulated registration failure"))
                } else {
                    loaded.set(true);
                    Ok(())
                }
            }
            _ => panic!("unexpected launchctl operation"),
        };
        let result = switch_job(&root, new, Some(old), control);
        let active = fs::read_link(root.join("current")).unwrap();
        fs::remove_file(root.join("current")).unwrap();
        fs::remove_dir(root).unwrap();
        assert_eq!(
            result.unwrap_err().to_string(),
            "simulated registration failure"
        );
        assert_eq!(active, old);
        assert!(loaded.get());
    }
}

fn switch(root: &Path, target: Option<&Path>) -> io::Result<()> {
    let current = root.join("current");
    let Some(target) = target else {
        return fs::remove_file(current);
    };
    let tmp = root.join(format!(".current-{:016x}", rand::random::<u64>()));
    symlink(target, &tmp)?;
    let result = fs::rename(&tmp, current);
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

fn launchctl(args: &[&str]) -> io::Result<()> {
    let output = Command::new("/bin/launchctl").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    let error = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "launchctl {}: {}",
        args[0],
        error.trim()
    )))
}
