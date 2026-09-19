//! What the window shows, and turning the engine on and off off the UI thread.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicIsize, Ordering},
    },
    time::Instant,
};

use windows::Win32::{
    Foundation::{HWND, LPARAM, WPARAM},
    UI::WindowsAndMessaging::{PostMessageW, WM_APP},
};

use crate::{
    engine::Engine,
    log, nrpt,
    proxy::{self, LOOPBACK},
};

pub const WM_MODEL: u32 = WM_APP + 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Power {
    Off,
    Starting,
    On,
    Stopping,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Svc {
    Off,
    Checking,
    Open(u32),
    Blocked,
}

pub struct Model {
    pub power: Power,
    pub error: Option<String>,
    /// Live check that the bypass gets through on this network.
    pub check: Svc,
}

pub static MODEL: Mutex<Model> = Mutex::new(Model {
    power: Power::Off,
    error: None,
    check: Svc::Off,
});

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);
static WINDOW: AtomicIsize = AtomicIsize::new(0);

pub fn set_window(h: HWND) {
    WINDOW.store(h.0 as isize, Ordering::SeqCst);
}

pub fn changed() {
    let h = HWND(WINDOW.load(Ordering::SeqCst) as *mut _);
    // SAFETY: posting to our own window; a stale handle just fails.
    unsafe {
        let _ = PostMessageW(Some(h), WM_MODEL, WPARAM(0), LPARAM(0));
    }
}

fn update(f: impl FnOnce(&mut Model)) {
    f(&mut MODEL.lock().unwrap());
    changed();
}

pub fn power() -> Power {
    MODEL.lock().unwrap().power
}

pub fn toggle() {
    match power() {
        Power::Off => start(),
        Power::On => stop(),
        _ => {}
    }
}

fn short(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(5) => "Windows denied access. Run EzPi as administrator.".into(),
        _ => {
            let s = e.to_string();
            s.split(" (os error").next().unwrap_or(&s).to_string()
        }
    }
}

fn start() {
    let _ = crate::dns::ON_NEW.set(changed);
    update(|m| {
        m.power = Power::Starting;
        m.error = None;
    });
    std::thread::spawn(|| {
        let e = match Engine::start(true) {
            Ok(e) => e,
            Err(err) => {
                log::line(&format!("start failed: {err}"));
                update(|m| {
                    m.power = Power::Off;
                    m.error = Some(short(&err));
                });
                return;
            }
        };
        let p = e.proxy.clone();
        *ENGINE.lock().unwrap() = Some(e);
        // Did Windows take the DNS rule? (It applies within a moment.)
        let mut dns_ok = false;
        for _ in 0..10 {
            if nrpt::system_lookup("discord.com") == Some(LOOPBACK) {
                dns_ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        if !dns_ok {
            log::line("the DNS rule did not take effect");
        }
        update(|m| {
            m.power = Power::On;
            m.check = Svc::Checking;
            if !dns_ok {
                m.error = Some(
                    "Windows didn't apply the DNS rule yet. Restart the PC if sites stay blocked."
                        .into(),
                );
            }
        });
        {
            let host = "discord.com";
            std::thread::spawn(move || {
                let t = Instant::now();
                let r = proxy::check(&p, host);
                let s = match r {
                    Ok(()) => Svc::Open(t.elapsed().as_millis() as u32),
                    Err(e) => {
                        log::line(&format!("check {host}: {e}"));
                        Svc::Blocked
                    }
                };
                update(|m| {
                    if m.power == Power::On {
                        m.check = s;
                    }
                });
            });
        }
    });
}

fn stop() {
    update(|m| m.power = Power::Stopping);
    std::thread::spawn(|| {
        if let Some(e) = ENGINE.lock().unwrap().take() {
            e.stop();
        }
        update(|m| {
            m.power = Power::Off;
            m.check = Svc::Off;
        });
    });
}

/// Synchronous: on exit or log-off, so the DNS rule never outlives EzPi.
pub fn shutdown() {
    if let Some(e) = ENGINE.lock().unwrap().take() {
        e.stop();
    }
}

/// Blocked sites opened through EzPi since it was turned on.
pub fn opened() -> usize {
    ENGINE
        .try_lock()
        .ok()
        .and_then(|g| g.as_ref().map(|e| e.resolver.opened.lock().unwrap().len()))
        .unwrap_or(0)
}
