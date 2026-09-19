# EzPi for Android

A no-root DPI bypass app for Android 8.0+ (API 26). It runs the **same engine as the
desktop version**: the ClientHello split and DoH re-resolution live in `../daemon/engine`
and are shared here, so the bypass logic is identical on PC and phone.

How it works: a `VpnService` captures all traffic into a TUN; a userspace
TCP/IP stack (gVisor netstack) terminates each flow and hands it to
`engine.Relay` (split + DoH); UDP/443 (QUIC) is rejected so apps fall back to
TCP. Everything stays on the phone; no root required.

## Use it

Open **EzPi**, tap the ring, and allow the VPN prompt once. The ring turns green and
the screen says **CONNECTED**. Tap it again to turn it off.

## Layout

- `app/` — Kotlin app: `MainActivity` (UI), `RingView` (the power ring) and
  `EzpiVpnService` (the VpnService).
- `ezpitun/` — Go library: gVisor netstack over the TUN fd, calls `engine.Relay`.
  Imports `ezpi/engine` from the daemon module via a `replace` directive.
- `probe/` — small TLS probe used to test a bypass through the tunnel.

## Toolchain

- Go, JDK 21, `gomobile` and `gobind`
  (`go install golang.org/x/mobile/cmd/gomobile@latest golang.org/x/mobile/cmd/gobind@latest`).
- Android SDK with `platforms;android-35` and **NDK r27** (`ndk;27.2.12479018`). Newer
  NDKs advertise API 36+, which gomobile rejects.
- Set `ANDROID_HOME` to the SDK and `ANDROID_NDK_HOME` to the NDK.
- Gradle comes from the wrapper (`./gradlew`). There's nothing to install.

## Build

```sh
cd android

# 1. Build the Go engine as an Android library (.aar) for arm64, armv7 and x86_64.
#    The 16KB max-page-size flag is REQUIRED for Android 15+ (16KB page devices).
cd ezpitun
gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 26 \
  -javapkg=com.ezpi -ldflags="-extldflags=-Wl,-z,max-page-size=16384" -o ezpitun.aar .
mkdir -p ../app/libs && cp ezpitun.aar ../app/libs/
cd ..

# 2. Build the APK.
./gradlew :app:assembleDebug

# 3. Install it on a phone with USB debugging on.
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The APK is signed with your local debug key, so it can't upgrade an install signed
with a different key. Uninstall the old app first.
