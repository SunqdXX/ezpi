//! EzPi for Windows. One small program: a window with an on/off button, a tray icon, and the
//! bypass engine (local DNS + SNI proxy + an NRPT rule) running inside the same process.
//!
//! Start-up: a normal (not elevated) start hands over to the installed task, so there is no UAC
//! prompt; only the very first start (or an update) asks once, to install. See `install.rs`.
#![cfg_attr(not(test), windows_subsystem = "windows")]

use ezpi::{app, engine, install, log, nrpt, ui};

use windows::{
    Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, GetLastError, LPARAM, WPARAM},
        System::Threading::CreateMutexW,
        UI::WindowsAndMessaging::{
            ASFW_ANY, AllowSetForegroundWindow, FindWindowW, MB_ICONERROR, MB_OK, MessageBoxW,
            PostMessageW,
        },
    },
    core::{HSTRING, PCWSTR, w},
};

fn error_box(text: &str) {
    // SAFETY: a modal message box with valid strings.
    unsafe {
        MessageBoxW(None, &HSTRING::from(text), w!("EzPi"), MB_OK | MB_ICONERROR);
    }
}

/// Bring an already running EzPi forward. True if there was one.
fn show_running() -> bool {
    // SAFETY: plain window calls; the running EzPi lets this message through UIPI.
    unsafe {
        match FindWindowW(ui::CLASS, PCWSTR::null()) {
            Ok(h) if !h.is_invalid() => {
                let _ = AllowSetForegroundWindow(ASFW_ANY);
                let _ = PostMessageW(Some(h), ui::WM_SHOWME, WPARAM(0), LPARAM(0));
                true
            }
            _ => false,
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |a: &str| args.iter().any(|x| x == a);
    // Test hook (not shown anywhere): run the engine without the window or the DNS rule.
    if args.get(1).map(String::as_str) == Some("--serve") {
        let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(60);
        let e = engine::Engine::start(false).expect("start");
        std::thread::sleep(std::time::Duration::from_secs(secs));
        e.stop();
        return;
    }
    let Ok(me) = std::env::current_exe() else {
        return;
    };

    // EZPI_PREVIEW=1: just show the window (development; the button then fails without rights).
    let preview = std::env::var_os("EZPI_PREVIEW").is_some();
    if !preview && !install::is_elevated() {
        if show_running() {
            return;
        }
        // SAFETY: lets the task-started EzPi take the foreground.
        unsafe {
            let _ = AllowSetForegroundWindow(ASFW_ANY);
        }
        if install::launch_via_task(&me) {
            return;
        }
        // First start (or a new version): ask once, to install.
        if !install::relaunch_elevated(&me, "--install") {
            error_box(
                "EzPi needs administrator rights once, to install itself. After that it starts without asking.",
            );
        }
        return;
    }

    // Elevated. Install (or update) when asked to or when nothing is installed yet.
    if !preview && (arg("--install") || !install::installed()) {
        match install::install(&me) {
            Ok(()) => {
                let inst = install::installed_exe();
                let here = std::fs::canonicalize(&me).ok();
                if here != std::fs::canonicalize(&inst).ok() && install::launch_via_task(&inst) {
                    return;
                }
            }
            Err(e) => {
                log::line(&format!("install failed: {e}"));
                error_box(&format!(
                    "EzPi could not install itself: {e}\nIt will run this time anyway."
                ));
            }
        }
    }

    // One EzPi at a time.
    // SAFETY: plain Win32 calls; the mutex handle lives for the whole process.
    unsafe {
        let _m = CreateMutexW(None, true, w!(r"Local\EzPi-single-instance"));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            show_running();
            return;
        }
    }
    // A rule left behind by a crash or power loss: nothing serves it now.
    if nrpt::present() {
        log::line("removing a DNS rule left from last time");
        let _ = nrpt::remove();
    }
    if let Err(e) = ui::run() {
        log::line(&format!("window: {e}"));
    }
    app::shutdown();
    // Everything is cleaned up (the DNS rule is gone); end now rather than wait on library
    // detach code during exit.
    std::process::exit(0);
}
