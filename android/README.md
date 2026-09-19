# EzPi for Android

A no-root DPI bypass app. It runs the **same engine as the desktop version** —
the ClientHello split and DoH re-resolution live in `../daemon/engine` and are
shared here, so the bypass logic is identical on PC and phone.

How it works: a `VpnService` captures all traffic into a TUN; a userspace
TCP/IP stack (gVisor netstack) terminates each flow and hands it to
`engine.Relay` (split + DoH); UDP/443 (QUIC) is rejected so apps fall back to
TCP. No root required.

## Layout

- `app/` — Kotlin app: `MainActivity` (UI) + `EzpiVpnService` (VpnService).
- `ezpitun/` — Go library: gVisor netstack over the TUN fd, calls `engine.Relay`.
  Imports `ezpi/engine` from the daemon module via a `replace` directive.
- `probe/` — small arm64 TLS probe used to test a bypass through the tunnel.

## Toolchain

- Go, Android SDK (platform-35, build-tools 35.0.0), **NDK r27** (newer NDKs
  advertise API 36+, which gomobile rejects), JDK 21, and `gomobile`/`gobind`.

## Build

```sh
# 1. Build the Go engine as an Android library (.aar).
#    The 16KB max-page-size flag is REQUIRED for Android 15+ (16KB page devices).
cd ezpitun
gomobile bind -target=android/arm64 -androidapi 24 -javapkg=com.ezpi \
  -ldflags="-extldflags=-Wl,-z,max-page-size=16384" -o ezpitun.aar .
cp ezpitun.aar ../app/libs/

# 2. Build the APK.
cd ..
gradle :app:assembleDebug

# 3. Install.
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Then open EzPi, tap **Connect**, allow the VPN prompt once.
