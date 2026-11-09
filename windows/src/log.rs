//! A small log file, %LOCALAPPDATA%\EzPi\ezpi.log (kept under 512 KB).

use std::{io::Write, path::PathBuf, sync::Mutex};

static LOCK: Mutex<()> = Mutex::new(());

pub fn path() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("EzPi");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("ezpi.log"))
}

pub fn line(msg: &str) {
    let _g = LOCK.lock();
    let Some(p) = path() else { return };
    if std::fs::metadata(&p).is_ok_and(|m| m.len() > 512 * 1024) {
        let _ = std::fs::rename(&p, p.with_extension("log.old"));
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
    {
        let _ = writeln!(f, "{secs} {msg}");
    }
}
