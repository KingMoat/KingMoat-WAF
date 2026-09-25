#!/usr/bin/env bash
# ============================================================================
# KingMoat WAF — one-click install for Debian 12+ / Ubuntu 24.04+ / openEuler 22.03+
#
# Usage:
#   curl -fsSL https://gitee.com/kingmoat/KingMoat-WAF/raw/main/deploy/install.sh | bash
#   bash install.sh                       # interactive
#   bash install.sh --version v0.7.0-rc1  # pin a version
#   bash install.sh --data-dir /opt/km    # non-interactive data dir
#   bash install.sh --uninstall           # remove everything
#
# What it does:
#   1. Detects distro and installs curl + tar + systemd (if missing)
#   2. Downloads the latest (or pinned) release from Gitee (fallback: GitHub)
#   3. Asks the user for install dir and data dir (with sane defaults)
#   4. Generates a minimal config.json and installs a systemd unit
#   5. Starts the service and verifies the console responds
#
# Requirements: root (or sudo), systemd, amd64 or arm64.
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Re-exec guard: when piped in (curl | bash), stdin is the script itself and
# the interactive "read" prompts below would swallow script lines. Re-run
# from a temp copy read from a file instead. KINGMOAT_REEXEC carries the
# copy's path into the second pass: it keeps this guard from re-triggering
# (fd0 is still not a tty there) and lets the EXIT trap below remove the
# copy.
# ---------------------------------------------------------------------------
if [[ ! -t 0 && -z "${KINGMOAT_REEXEC:-}" ]]; then
    _reexec="$(mktemp /tmp/kingmoat-install.XXXXXX.sh)"
    cat > "$_reexec"
    if [[ ! -s "$_reexec" ]]; then
        rm -f "$_reexec"
        printf '\033[1;31m[error]\033[0m stdin is not a terminal and no script was piped in. Run: bash %s\n' "$0" >&2
        exit 1
    fi
    KINGMOAT_REEXEC="$_reexec" exec bash "$_reexec" "$@"
fi
if [[ -n "${KINGMOAT_REEXEC:-}" ]]; then
    trap 'rm -f "$KINGMOAT_REEXEC" 2>/dev/null; :' EXIT
fi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly GITEE_API="https://gitee.com/api/v5/repos/kingmoat/KingMoat-WAF"
readonly GITEE_DL="https://gitee.com/kingmoat/KingMoat-WAF/releases/download"
readonly GITHUB_DL="https://github.com/kingmoat/KingMoat-WAF/releases/download"
readonly GITHUB_API="https://api.github.com/repos/kingmoat/KingMoat-WAF"
# CONSOLE_PORT_DEFAULT is deliberately NOT readonly: the interactive prompt
# below may replace it (assigning a readonly var aborts under set -e).
CONSOLE_PORT_DEFAULT="28443"
readonly DATA_PORT_DEFAULT="18080"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

need_root() {
    if [[ $EUID -ne 0 ]]; then
        err "please run as root (sudo bash $0)"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PINNED_VERSION=""
DATA_DIR=""
UNINSTALL=false
NONINTERACTIVE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)      [[ $# -ge 2 ]] || err "--version requires a value"; PINNED_VERSION="$2"; shift 2 ;;
        --data-dir)     [[ $# -ge 2 ]] || err "--data-dir requires a value"; DATA_DIR="$2"; shift 2 ;;
        --uninstall)    UNINSTALL=true; shift ;;
        -y|--yes)       NONINTERACTIVE=true; shift ;;
        *)              err "unknown option: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------
if $UNINSTALL; then
    need_root
    # Prefer the install metadata written by a previous run of this script
    # (custom install dirs); fall back to the default location.
    INSTALL_DIR=/opt/kingmoat
    if [[ -f /etc/kingmoat-install.conf ]]; then
        # shellcheck source=/dev/null
        . /etc/kingmoat-install.conf
    fi
    log "stopping and disabling kingmoat.service ..."
    systemctl disable --now kingmoat.service 2>/dev/null || true
    rm -f /etc/systemd/system/kingmoat.service /etc/kingmoat-install.conf
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    warn "data dir NOT removed. Remove manually if desired:"
    warn "  rm -rf ${DATA_DIR:-/var/lib/kingmoat}"
    log "uninstall done."
    exit 0
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
need_root

if ! command -v systemctl &>/dev/null; then
    err "systemd not found — this script requires a systemd-based distro."
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  PKG_ARCH="amd64" ;;
    aarch64) PKG_ARCH="arm64" ;;
    *)       err "unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac

# Detect distro for package manager
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VER="${VERSION_ID:-0}"
    else
        err "cannot detect distro (/etc/os-release missing)"
    fi
    case "$DISTRO_ID" in
        debian|ubuntu)  PKG_MGR="apt" ;;
        openEuler|openEuler-leap|anolis|centos|rhel|fedora) PKG_MGR="dnf" ;;
        *)              warn "unknown distro $DISTRO_ID — trying both apt and dnf"; PKG_MGR="auto" ;;
    esac
}
detect_distro

install_deps() {
    local missing=()
    command -v curl &>/dev/null || missing+=("curl")
    command -v tar  &>/dev/null || missing+=("tar")
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "installing missing dependencies: ${missing[*]}"
        case "$PKG_MGR" in
            apt)  apt-get update -qq && apt-get install -y -qq "${missing[@]}" ;;
            dnf)  dnf install -y -q "${missing[@]}" ;;
            auto) apt-get install -y "${missing[@]}" 2>/dev/null || dnf install -y "${missing[@]}" ;;
        esac
    fi
    command -v curl &>/dev/null || err "curl is required but could not be installed"
    command -v tar  &>/dev/null || err "tar is required but could not be installed"
}
install_deps

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
resolve_version() {
    if [[ -n "$PINNED_VERSION" ]]; then
        RELEASE_TAG="$PINNED_VERSION"
        log "using pinned version: $RELEASE_TAG"
        return
    fi
    log "fetching latest release tag from Gitee ..."
    RELEASE_TAG=$(curl -sfSL --max-time 15 "${GITEE_API}/releases/latest" 2>/dev/null \
        | grep -oP '"tag_name"\s*:\s*"\K[^"]+' | head -1) || true
    if [[ -z "$RELEASE_TAG" ]]; then
        log "Gitee API failed, trying GitHub ..."
        RELEASE_TAG=$(curl -sfSL --max-time 15 "${GITHUB_API}/releases/latest" 2>/dev/null \
            | grep -oP '"tag_name"\s*:\s*"\K[^"]+' | head -1) || true
    fi
    [[ -z "$RELEASE_TAG" ]] && err "cannot resolve latest release tag. Use --version <tag> to pin."
    log "latest release: $RELEASE_TAG"
}
resolve_version

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
TMPDIR_INSTALL=$(mktemp -d /tmp/kingmoat-install.XXXXXX)
# Also remove the re-exec copy of this script (path in KINGMOAT_REEXEC); the
# trailing ":" keeps a failed rm from overriding the script's exit status.
trap 'rm -rf "$TMPDIR_INSTALL"; if [[ -n "${KINGMOAT_REEXEC:-}" ]]; then rm -f "$KINGMOAT_REEXEC" 2>/dev/null; fi; :' EXIT

PKG_NAME="kingmoat_${RELEASE_TAG}_linux_${PKG_ARCH}"
# Gitee asset naming convention (no dot in tag): tar.gz
ASSET_FILE="${PKG_NAME}.tar.gz"
DL_URL_GITEE="${GITEE_DL}/${RELEASE_TAG}/${ASSET_FILE}"
DL_URL_GITHUB="${GITHUB_DL}/${RELEASE_TAG}/${ASSET_FILE}"

download_release() {
    log "downloading $ASSET_FILE ..."
    if curl -fSL --max-time 300 --retry 2 -o "$TMPDIR_INSTALL/$ASSET_FILE" "$DL_URL_GITEE" 2>/dev/null; then
        log "downloaded from Gitee ✓"
        return 0
    fi
    log "Gitee download failed, trying GitHub ..."
    if curl -fSL --max-time 300 --retry 2 -o "$TMPDIR_INSTALL/$ASSET_FILE" "$DL_URL_GITHUB" 2>/dev/null; then
        log "downloaded from GitHub ✓"
        return 0
    fi
    err "download failed from both mirrors. Check network or use --version to pin a valid tag."
}
download_release

# Verify checksum (fail-closed: refuse to install unverified binaries)
log "verifying checksum ..."
if ! curl -fSL --max-time 30 -o "$TMPDIR_INSTALL/checksums.txt" "${GITEE_DL}/${RELEASE_TAG}/checksums.txt" 2>/dev/null; then
    err "checksums.txt not available for $RELEASE_TAG - refusing to install unverified binaries"
fi
EXPECTED=$(grep -E "(^|[[:space:]])${ASSET_FILE}([[:space:]]|$)" "$TMPDIR_INSTALL/checksums.txt" | awk '{print $1}' | head -1)
ACTUAL=$(sha256sum "$TMPDIR_INSTALL/$ASSET_FILE" | awk '{print $1}')
if [[ -z "$EXPECTED" ]]; then
    err "$ASSET_FILE not listed in checksums.txt"
fi
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    err "checksum mismatch! expected=$EXPECTED actual=$ACTUAL"
fi
log "checksum verified ✓"

# Extract
log "extracting ..."
tar -xzf "$TMPDIR_INSTALL/$ASSET_FILE" -C "$TMPDIR_INSTALL"
if [[ ! -f "$TMPDIR_INSTALL/kingmoat" ]]; then
    # Some archives wrap in a subdirectory
    SUBDIR=$(find "$TMPDIR_INSTALL" -type d -name "kingmoat*" | head -1)
    [[ -n "$SUBDIR" ]] && mv "$SUBDIR"/* "$TMPDIR_INSTALL/"
fi
[[ -f "$TMPDIR_INSTALL/kingmoat" ]] || err "kingmoat binary not found in archive"
log "extracted ✓"
chmod +x "$TMPDIR_INSTALL/kingmoat"
[[ -f "$TMPDIR_INSTALL/kingmoat-cli" ]] && chmod +x "$TMPDIR_INSTALL/kingmoat-cli"

# ---------------------------------------------------------------------------
# Interactive directory selection
# ---------------------------------------------------------------------------
INSTALL_DIR="/opt/kingmoat"
if [[ $NONINTERACTIVE == false ]]; then
    echo ""
    printf '\033[1;36m── 安装目录 ──\033[0m\n'
    read -rp "安装目录 [$INSTALL_DIR]: " INPUT_INSTALL
    [[ -n "$INPUT_INSTALL" ]] && INSTALL_DIR="$INPUT_INSTALL"

    printf '\033[1;36m── 数据目录 ──\033[0m\n'
    echo "数据目录存放 SQLite 配置库、审计日志与证书（必须是本机磁盘，不能是 NFS/SMB）。"
    DEFAULT_DATA="/var/lib/kingmoat"
    read -rp "数据目录 [$DEFAULT_DATA]: " INPUT_DATA
    if [[ -n "$INPUT_DATA" ]]; then
        DATA_DIR="$INPUT_DATA"
    elif [[ -z "$DATA_DIR" ]]; then
        DATA_DIR="$DEFAULT_DATA"
    fi

    printf '\033[1;36m── 控制台端口 ──\033[0m\n'
    read -rp "控制台 HTTPS 端口 [$CONSOLE_PORT_DEFAULT]: " INPUT_PORT
    [[ -n "$INPUT_PORT" ]] && CONSOLE_PORT_DEFAULT="$INPUT_PORT"
fi

# Validate data dir is on a local filesystem (create it first so df can
# resolve the mount instead of silently failing on a missing path)
DATA_DIR="${DATA_DIR:-/var/lib/kingmoat}"
mkdir -p "$DATA_DIR" 2>/dev/null || true
if df "$DATA_DIR" 2>/dev/null | tail -1 | grep -qE 'nfs|cifs|smbfs|fuse'; then
    err "data dir is on a network filesystem - SQLite requires a local disk"
fi

# Path sanity for the systemd sandbox: ProtectHome=true hides /home and
# /root entirely, and spaces cannot be carried through ExecStart safely.
for _p in "$INSTALL_DIR" "$DATA_DIR"; do
    case "$_p" in
        *' '*) err "path contains spaces (unsupported): $_p" ;;
        /home|/home/*|/root|/root/*) err "path under /home or /root is hidden by systemd ProtectHome=true: $_p" ;;
    esac
done

# Console port sanity before it lands in ExecStart
if ! [[ "$CONSOLE_PORT_DEFAULT" =~ ^[0-9]+$ ]] || (( CONSOLE_PORT_DEFAULT < 1 || CONSOLE_PORT_DEFAULT > 65535 )); then
    err "invalid console port: $CONSOLE_PORT_DEFAULT (need 1-65535)"
fi

# ---------------------------------------------------------------------------
# Install files
# ---------------------------------------------------------------------------
# Upgrades: stop the service before replacing the running binary (an in-place
# cp over a live executable fails with ETXTBSY and set -e aborts midway).
if systemctl cat kingmoat.service &>/dev/null && systemctl is-active --quiet kingmoat.service; then
    log "stopping existing kingmoat.service for upgrade ..."
    systemctl stop kingmoat.service
fi
log "installing to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR/logs" "$DATA_DIR/archive"
cp "$TMPDIR_INSTALL/kingmoat"      "$INSTALL_DIR/kingmoat"
[[ -f "$TMPDIR_INSTALL/kingmoat-cli" ]]      && cp "$TMPDIR_INSTALL/kingmoat-cli"      "$INSTALL_DIR/kingmoat-cli"
[[ -f "$TMPDIR_INSTALL/README.md" ]]         && cp "$TMPDIR_INSTALL/README.md"         "$INSTALL_DIR/"
[[ -f "$TMPDIR_INSTALL/LICENSE" ]]           && cp "$TMPDIR_INSTALL/LICENSE"           "$INSTALL_DIR/"
[[ -f "$TMPDIR_INSTALL/NOTICE" ]]            && cp "$TMPDIR_INSTALL/NOTICE"            "$INSTALL_DIR/"
[[ -f "$TMPDIR_INSTALL/THIRD-PARTY-LICENSES" ]] && cp "$TMPDIR_INSTALL/THIRD-PARTY-LICENSES" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/kingmoat"
[[ -f "$INSTALL_DIR/kingmoat-cli" ]] && chmod +x "$INSTALL_DIR/kingmoat-cli"

# ---------------------------------------------------------------------------
# Generate config.json (if not upgrading)
# ---------------------------------------------------------------------------
CONFIG_FILE="$DATA_DIR/config.json"
if [[ ! -f "$CONFIG_FILE" ]]; then
    log "generating $CONFIG_FILE ..."
    cat > "$CONFIG_FILE" <<JSONEOF
{
  "listen_http": "127.0.0.1:${DATA_PORT_DEFAULT}",
  "listen_https": "",
  "audit_log_dir": "${DATA_DIR}/logs",
  "sites": [
    {
      "domains": ["localhost", "127.0.0.1"],
      "mode": "monitor",
      "upstream": { "nodes": [{ "address": "127.0.0.1:9000" }] },
      "waf": { "enabled": true }
    }
  ]
}
JSONEOF
    log "config generated (monitor mode — safe for first-run)"
fi

# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------
log "installing systemd unit ..."
cat > /etc/systemd/system/kingmoat.service <<UNIT
[Unit]
Description=KingMoat WAF (all-in-one: data plane + console)
Documentation=https://gitee.com/kingmoat/KingMoat-WAF
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
StateDirectory=kingmoat
ConfigurationDirectory=kingmoat
ReadWritePaths=${DATA_DIR} ${INSTALL_DIR}
WorkingDirectory=${DATA_DIR}
ExecStart="${INSTALL_DIR}/kingmoat" -config "${CONFIG_FILE}" -console-addr 0.0.0.0:${CONSOLE_PORT_DEFAULT} -console-db "${DATA_DIR}/kingmoat.db"
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
log "starting kingmoat.service ..."
systemctl enable --now kingmoat.service
sleep 2

if systemctl is-active --quiet kingmoat.service; then
    log "service is running ✓"
else
    err "service failed to start. Check: journalctl -u kingmoat -n 30"
fi

# Smoke check
sleep 1
HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:${CONSOLE_PORT_DEFAULT}/" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
    log "console is responding ✓"
else
    warn "console returned HTTP $HTTP_CODE (may still be starting)"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
printf '\033[1;32m════════════════════════════════════════════════\033[0m\n'
printf '\033[1;32m KingMoat WAF installed successfully!\033[0m\n'
printf '\033[1;32m════════════════════════════════════════════════\033[0m\n'
echo ""
echo "  Console:  https://$(hostname -I | awk '{print $1}'):${CONSOLE_PORT_DEFAULT}"
echo "            https://127.0.0.1:${CONSOLE_PORT_DEFAULT}  (local, self-signed cert)"
echo "  Account:  kmadmin / KingMoat@2026  (change password at first login!)"
echo "  Config:   $CONFIG_FILE"
echo "  Data:     $DATA_DIR"
echo "  Logs:     journalctl -u kingmoat -f"
echo ""
echo "  Useful commands:"
echo "    systemctl status kingmoat"
echo "    systemctl restart kingmoat"
echo "    ${INSTALL_DIR}/kingmoat-cli hash-password -password '...'"
echo ""

# Persist install locations for uninstall / future upgrades
cat > /etc/kingmoat-install.conf <<META
INSTALL_DIR="$INSTALL_DIR"
DATA_DIR="$DATA_DIR"
META
chmod 600 /etc/kingmoat-install.conf
