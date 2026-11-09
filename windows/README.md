# EzPi for Windows

One small exe (about 600 KB). No driver, no VPN, nothing else to install.

## Use it

1. Download `EzPi-windows-x64.exe` from the release and open it.
2. Windows may say "Windows protected your PC" because the exe isn't signed: click
   **More info → Run anyway**.
3. The first time, it asks for administrator rights once (**Yes**). It installs itself to
   `C:\Program Files\EzPi` and puts an **EzPi** shortcut on the desktop and in the Start menu.
   After that it opens without asking.
4. Press the big button. When it turns green, blocked sites and apps open normally.

Closing the window keeps it running in the tray. Right-click the tray icon to turn it off, quit,
or uninstall. Uninstalling puts everything back.

## How it works

The same split-ClientHello idea as the Linux proxy engine, without any driver:

- While EzPi is on, a Windows DNS policy rule (NRPT) sends DNS questions to EzPi on
  `127.65.80.1`.
- Names the ISP answers with its block page (learned at start), refuses to answer, or that are
  on a short built-in list (Roblox, Discord) get `127.65.80.1` as their address. Everything else
  is forwarded to the PC's normal DNS servers and comes back unchanged, so unblocked sites keep
  their usual speed.
- Connections to `127.65.80.1:443` reach EzPi's SNI proxy. It reads the hostname from the
  ClientHello, resolves the real address over DNS-over-HTTPS (WinHTTP), and sends the ClientHello
  split into TLS records inside the hostname (`record-sni`, with fallbacks). TLS stays end to end;
  EzPi never decrypts anything. Port 80 is forwarded with the `Host` header masked.
- Turning it off (or quitting, or signing out) removes the rule. A rule left behind by a crash is
  removed at the next start, and the rule lists the normal DNS servers as a fallback.

Administrator rights are only needed to write the NRPT rule. The install step creates a Task
Scheduler task that runs the installed copy with highest privileges, so later starts show no UAC
prompt; only an administrator can change the exe in Program Files.

Log: `%LOCALAPPDATA%\EzPi\ezpi.log`.

Tested on Windows 11 with Türk Telekom. Other ISPs may block differently.

## Build

Rust (MSVC toolchain) and the Visual Studio Build Tools:

```
cd windows
cargo test --release
cargo build --release
```

The exe is `target\release\EzPi.exe`. The C runtime is linked statically (`.cargo/config.toml`).
