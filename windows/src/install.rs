//! Ask for administrator rights once, at install, instead of at every start.
//!
//! The first run asks Windows for elevation (one UAC prompt), copies EzPi to
//! `C:\Program Files\EzPi` (only administrators can change files there, so nobody can swap the
//! exe), and creates a Task Scheduler task that runs that exe with the user's full rights. The
//! desktop and Start menu shortcuts open the installed exe, which only asks the task to start the
//! real EzPi and exits, so later starts show no prompt.
#![allow(unsafe_code)]

use std::{
    io,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                IPersistFile,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
        UI::{
            Shell::{
                FOLDERID_CommonPrograms, FOLDERID_Desktop, IShellLinkW, KF_FLAG_DEFAULT,
                SHGetKnownFolderPath, ShellExecuteW, ShellLink,
            },
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    },
    core::{HSTRING, Interface, PCWSTR, w},
};

use crate::log;

pub const TASK: &str = "EzPi";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .unwrap_or_else(|| r"C:\Program Files".into());
    PathBuf::from(pf).join("EzPi")
}

pub fn installed_exe() -> PathBuf {
    install_dir().join("EzPi.exe")
}

pub fn is_elevated() -> bool {
    // SAFETY: querying our own process token; the handle is closed.
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).is_err() {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            tok,
            TokenElevation,
            Some(std::ptr::from_mut(&mut e).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(tok);
        ok && e.TokenIsElevated != 0
    }
}

fn schtasks(args: &[&str]) -> io::Result<bool> {
    Ok(Command::new("schtasks.exe")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()?
        .success())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// The installed copy is this very program (same bytes), so nothing needs updating.
fn up_to_date(me: &Path) -> bool {
    let inst = installed_exe();
    if same_file(me, &inst) {
        return true;
    }
    match (std::fs::read(me), std::fs::read(&inst)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Whether EzPi is installed and the task exists.
pub fn installed() -> bool {
    installed_exe().is_file() && schtasks(&["/Query", "/TN", TASK]).unwrap_or(false)
}

/// Not elevated: start EzPi through the task. Returns false if that isn't possible yet.
pub fn launch_via_task(me: &Path) -> bool {
    if !installed() || !up_to_date(me) {
        return false;
    }
    schtasks(&["/Run", "/TN", TASK]).unwrap_or(false)
}

/// Start this exe again with administrator rights (the one UAC prompt).
pub fn relaunch_elevated(me: &Path, args: &str) -> bool {
    // SAFETY: ShellExecuteW with valid strings; the result is an HINSTANCE-like status code.
    let r = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            &HSTRING::from(me.as_os_str()),
            &HSTRING::from(args),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    r.0 as isize > 32
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn task_xml(exe: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Starts EzPi without a UAC prompt.</Description></RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>"{}"</Command><Arguments>--run</Arguments></Exec>
  </Actions>
</Task>
"#,
        xml_escape(&exe.display().to_string())
    )
}

fn known_folder(id: &windows::core::GUID) -> Option<PathBuf> {
    // SAFETY: the returned string is CoTaskMemAlloc'd and freed after copying.
    unsafe {
        let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let s = p.to_string().ok();
        windows::Win32::System::Com::CoTaskMemFree(Some(p.0.cast()));
        s.map(PathBuf::from)
    }
}

fn shortcut(at: &Path, target: &Path) -> windows::core::Result<()> {
    // SAFETY: standard IShellLink/IPersistFile use on this thread.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(&HSTRING::from(target.as_os_str()))?;
        link.SetDescription(w!("EzPi: unblock sites and apps without a VPN"))?;
        if let Some(dir) = target.parent() {
            link.SetWorkingDirectory(&HSTRING::from(dir.as_os_str()))?;
        }
        link.SetIconLocation(&HSTRING::from(target.as_os_str()), 0)?;
        link.cast::<IPersistFile>()?
            .Save(&HSTRING::from(at.as_os_str()), true)
    }
}

fn shortcut_paths() -> Vec<PathBuf> {
    [
        known_folder(&FOLDERID_Desktop),
        known_folder(&FOLDERID_CommonPrograms),
    ]
    .into_iter()
    .flatten()
    .map(|d| d.join("EzPi.lnk"))
    .collect()
}

/// Elevated: copy EzPi into Program Files, create the task and the shortcuts.
pub fn install(me: &Path) -> io::Result<()> {
    let dir = install_dir();
    std::fs::create_dir_all(&dir)?;
    let exe = installed_exe();
    if !same_file(me, &exe) {
        // A running old copy keeps its file locked: move it out of the way first.
        if exe.exists() {
            let old = dir.join("EzPi.old");
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::rename(&exe, &old);
        }
        std::fs::copy(me, &exe)?;
    }
    let xml = std::env::temp_dir().join(format!("ezpi-task-{}.xml", std::process::id()));
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(task_xml(&exe).encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    std::fs::write(&xml, utf16)?;
    let ok = schtasks(&["/Create", "/TN", TASK, "/XML", &xml.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&xml);
    if !ok? {
        return Err(io::Error::other("could not create the start-up task"));
    }
    for at in shortcut_paths() {
        if let Err(e) = shortcut(&at, &exe) {
            log::line(&format!("shortcut {}: {e}", at.display()));
        }
    }
    log::line(&format!("installed to {}", dir.display()));
    Ok(())
}

/// Elevated: remove the task, the shortcuts and the program folder.
pub fn uninstall() {
    let _ = schtasks(&["/Delete", "/TN", TASK, "/F"]);
    for at in shortcut_paths() {
        let _ = std::fs::remove_file(at);
    }
    // The running exe can't delete itself: a hidden cmd does it a moment after we exit.
    let dir = install_dir();
    let _ = Command::new("cmd.exe")
        .arg("/C")
        .raw_arg(format!(
            "ping -n 3 127.0.0.1 >NUL & rmdir /S /Q \"{}\"",
            dir.display()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    log::line("uninstalled");
}
