#!/usr/bin/env bash
# EzPi installer.
#
#   sudo ./install.sh              install
#   sudo ./install.sh --uninstall  remove
#
# EzPi is a single self-contained program. There is nothing else to install:
# no Python, no Qt, no runtime, no virtual environment.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=/usr/local/bin
APPS=/usr/local/share/applications
ICONS=/usr/local/share/icons/hicolor
ETC=/etc/ezpi

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this with sudo:  sudo ./install.sh" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# ensure_firewall makes sure the kernel packet tools EzPi needs are present.
# EzPi can drive traffic through either nftables (modern) or iptables (older);
# it needs at least one. If neither is installed, this offers to install
# nftables using whatever package manager the system has, so a fresh machine
# goes from zero to working without the user hunting down dependencies.
# ---------------------------------------------------------------------------
ensure_firewall() {
    if command -v nft >/dev/null 2>&1; then
        echo ":: firewall: nftables present"
        return 0
    fi
    if command -v iptables >/dev/null 2>&1; then
        echo ":: firewall: iptables present (nftables not found, will use iptables)"
        return 0
    fi

    echo ":: neither nftables nor iptables is installed."
    local pm="" cmd=""
    if   command -v pacman  >/dev/null 2>&1; then pm=pacman;  cmd="pacman -S --noconfirm --needed nftables"
    elif command -v apt-get >/dev/null 2>&1; then pm=apt;     cmd="apt-get update && apt-get install -y nftables"
    elif command -v dnf     >/dev/null 2>&1; then pm=dnf;     cmd="dnf install -y nftables"
    elif command -v zypper  >/dev/null 2>&1; then pm=zypper;  cmd="zypper install -y nftables"
    elif command -v apk     >/dev/null 2>&1; then pm=apk;     cmd="apk add nftables"
    fi

    if [[ -z "$pm" ]]; then
        echo "!! Could not find a known package manager. Install 'nftables' or 'iptables'" >&2
        echo "   with your distribution's tools, then run this again." >&2
        exit 1
    fi

    # Non-interactive installs (piped) proceed automatically; a terminal asks.
    local ans="y"
    if [[ -t 0 ]]; then
        read -r -p "   Install nftables now with $pm? [Y/n] " ans || ans="y"
    fi
    case "${ans:-y}" in
        n|N) echo "!! nftables is required. Install it and run this again." >&2; exit 1 ;;
    esac

    echo ":: installing nftables via $pm"
    if ! eval "$cmd"; then
        echo "!! Installing nftables failed. Do it manually, then run this again." >&2
        exit 1
    fi
    modprobe nf_tables 2>/dev/null || true
    echo ":: nftables installed"
}

if [[ ${1:-} == "--uninstall" ]]; then
    echo ":: stopping EzPi"
    systemctl disable --now ezpi.service 2>/dev/null || true
    nft delete table ip ezpi 2>/dev/null || true

    echo ":: removing files"
    rm -f "$BIN/ezpi" "$BIN/ezpid" \
          /etc/systemd/system/ezpi.service \
          /etc/polkit-1/rules.d/49-ezpi.rules \
          "$APPS/ezpi.desktop"
    rm -f "$ICONS"/*/apps/ezpi.png 2>/dev/null || true
    rm -rf /usr/local/share/ezpi
    systemctl daemon-reload
    echo ":: removed. Settings kept in $ETC"
    exit 0
fi

ensure_firewall

# Prefer a binary shipped alongside this script; build one only if it is
# missing and Go happens to be installed.
EXE="$SRC/ezpi"
if [[ ! -x "$EXE" ]]; then
    if [[ -d "$SRC/daemon" ]] && command -v go >/dev/null; then
        echo ":: building"
        ( cd "$SRC/daemon" && go build -ldflags="-s -w" -o "$SRC/ezpi" . )
    else
        echo "No ezpi binary found next to this script, and Go is not installed." >&2
        echo "Download the release archive rather than a source checkout." >&2
        exit 1
    fi
fi

# Remember whether it was already protecting, so an upgrade does not silently
# leave the old engine running from a binary that is about to be replaced.
WAS_ACTIVE=0
systemctl is-active --quiet ezpi.service && WAS_ACTIVE=1

echo ":: installing"
install -Dm755 "$EXE" "$BIN/ezpi"
# Older versions shipped a separate engine binary and a Python interface.
# It is one self-contained program now, so clear those out.
rm -f "$BIN/ezpid"
rm -rf /usr/local/share/ezpi

install -Dm644 "$SRC/packaging/linux/ezpi.service"  /etc/systemd/system/ezpi.service
install -Dm644 "$SRC/packaging/linux/49-ezpi.rules" /etc/polkit-1/rules.d/49-ezpi.rules

# Never overwrite settings someone has edited.
if [[ ! -f "$ETC/config.json" ]]; then
    install -Dm644 "$SRC/packaging/linux/config.json" "$ETC/config.json"
fi

systemctl daemon-reload
if [[ $WAS_ACTIVE -eq 1 ]]; then
    echo ":: restarting (it was already on)"
    systemctl restart ezpi.service || true
fi

cat <<'DONE'

:: Done.

   Turn it on:     ezpi --enable
   Turn it off:    ezpi --disable
   Check it:       ezpi              (or: ezpi --status)
   Test it works:  ezpi --check

   Nothing is running yet, and no firewall rules are loaded until you enable it.

   To remove it:  sudo ./install.sh --uninstall

DONE
