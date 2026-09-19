# EzPi

```
 _______   ________  ________  ___
|\  ___ \ |\_____  \|\   __  \|\  \
\ \   __/| \|___/  /\ \  \|\  \ \  \
 \ \  \_|/__   /  / /\ \   ____\ \  \
  \ \  \_|\ \ /  /_/__\ \  \___|\ \  \
   \ \_______\\________\ \__\    \ \__\
    \|_______|\|_______|\|__|     \|__|
```

**Unblock the sites and apps your internet provider blocks — without a VPN.**

EzPi is a tiny DPI bypass. No VPN, no speed hit, no account, nothing to configure. It never decrypts your traffic and installs no certificate — it just hides the one thing the block looks at: the site's **name**.

Runs on **Linux**, **Android**, and **Windows**. Same idea everywhere — proven against Turkish ISPs on both Wi-Fi and mobile data.

---

## See it

| Android | Windows |
|:---:|:---:|
| <img src="android/screenshots/connected.png" width="260" alt="EzPi on Android"> | <img src="screenshots/windows.jpg" width="260" alt="EzPi on Windows"> |

*Linux is a terminal tool — one word toggles it, and `ezpi --wizard` prints the logo above.*

---

## How it works

When you open a site, everything is encrypted **except the site's name** — it's sent in the clear during the TLS handshake, and that name is exactly what your provider matches to block you.

EzPi fixes that, entirely on your own device:

1. **Finds the real address itself** over DNS-over-HTTPS — so the provider can't feed you a fake one (DNS poisoning).
2. **Splits the name across packets** so the filter can't read it in one piece.
3. **Closes the side doors** (QUIC) so nothing slips past unprotected.

The real server still understands everything. Your connection stays **end-to-end encrypted** — EzPi can't read it, and neither can your provider.

---

## Get it

### 🐧 Linux
```sh
sudo ./install.sh      # install — sets everything up for you
ezpi                   # type it → ON.   type it again → OFF.
ezpi --check           # is it actually beating your provider?
```
~15 MB, runs in the background, zero config. Remove it with `sudo ./install.sh --uninstall`.

### 📱 Android
No root needed. Grab it from [`android/`](android/README.md), open **EzPi**, tap **Connect**, and allow the VPN prompt once. Same bypass, on Wi-Fi **and** mobile data.

### 🪟 Windows
**[⬇ Download EzPi-windows-x64.exe](https://github.com/SunqdXX/ezpi/releases/latest/download/EzPi-windows-x64.exe)**

One ~600 KB exe, no driver. Run it once (one admin prompt), press the big button. Full details and build steps: [`windows/`](windows/README.md).

---

## Build from source
- **Linux + the shared engine** — Go: `cd daemon && make build && make test`
- **Android** — Go + gomobile: [android/README.md](android/README.md)
- **Windows** — Rust: [windows/README.md](windows/README.md)

---

## Credits
- **Linux, Android & the shared engine** — [@SunqdXX](https://github.com/SunqdXX)
- **Windows** — [@yasinlol](https://github.com/yasinlol)

## License
MIT. Do whatever you want with it. See [LICENSE](LICENSE).

---

*#### Windows users do NOT deserve My Projects — so [@yasinlol](https://github.com/yasinlol) went and built them one anyway.*
