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
        err "please run as root: re-run with sudo ('sudo bash install.sh', or re-run the piped install command with sudo)"
    fi
}

# Set to true after an upgrade has stopped a running service and back to
# false once the service is confirmed running again; cleanup() reads it to
# best-effort restart the service on any aborted exit path (no rollback).
SERVICE_STOPPED=false

# ---------------------------------------------------------------------------
# Cleanup: the single EXIT hook shared by every exit path (normal, error,
# signal). TERM/INT are converted to exit 143 so the same hook runs. Every
# step is fault-tolerant: a failing rm must not abort the remaining cleanup,
# and the trap must never mask the script's own exit status.
# ---------------------------------------------------------------------------
cleanup() {
    trap - EXIT
    if [[ "${SERVICE_STOPPED:-false}" == true ]]; then
        # Upgrade aborted between "systemctl stop" and a verified running
        # service: best-effort restart, no version rollback. A new binary
        # that cannot start is left failed on purpose - the original error
        # must stay visible.
        warn "attempting to restart kingmoat.service after aborted run ..."
        systemctl start kingmoat.service 2>/dev/null || true
    fi
    if [[ -n "${TMPDIR_INSTALL:-}" ]]; then
        rm -rf "$TMPDIR_INSTALL" 2>/dev/null || true
    fi
    if [[ -n "${KINGMOAT_REEXEC:-}" ]]; then
        rm -f "$KINGMOAT_REEXEC" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 143' TERM INT

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PINNED_VERSION=""
DATA_DIR=""
UNINSTALL=false
NONINTERACTIVE=false

# Parsing consumes "$@" via shift; keep the original list so the piped
# re-exec guard below can hand the exact same options to the second pass
# (parsing is idempotent and side-effect free).
_ORIG_ARGS=("$@")

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
# Re-exec guard: when piped in (curl | bash), stdin is the script itself and
# the interactive "read" prompts below would swallow script lines. Re-run
# from a temp copy read from a file instead. KINGMOAT_REEXEC carries the
# copy's path into the second pass: it keeps this guard from re-triggering
# and lets the EXIT trap remove the copy.
#
# The guard only applies to runs that actually consume stdin interactively:
# -y (non-interactive) and --uninstall never read from stdin, so they
# proceed even on a non-tty fd0 (CI, `ssh host 'bash install.sh -y'`).
# ---------------------------------------------------------------------------
# Only trust a caller-provided KINGMOAT_REEXEC that looks like what this
# script itself sets for the second pass: an absolute path under
# /tmp/kingmoat-install.* pointing at an existing file. Anything else is
# dropped so a forged value can neither bypass the guard nor leak into the
# cleanup rm below.
KINGMOAT_REEXEC="${KINGMOAT_REEXEC:-}"
if [[ -n "$KINGMOAT_REEXEC" && ( $KINGMOAT_REEXEC != /* || $KINGMOAT_REEXEC != /tmp/kingmoat-install.* || ! -f $KINGMOAT_REEXEC ) ]]; then
    KINGMOAT_REEXEC=""
fi
if [[ ! -t 0 && -z "$KINGMOAT_REEXEC" && $NONINTERACTIVE == false && $UNINSTALL == false ]]; then
    _reexec="$(mktemp /tmp/kingmoat-install.XXXXXX)"
    cat > "$_reexec"
    if [[ ! -s "$_reexec" ]]; then
        rm -f "$_reexec"
        printf '\033[1;31m[error]\033[0m stdin is not a terminal and no script was piped in.\n' >&2
        printf '\033[1;31m[error]\033[0m run: curl -fsSL https://gitee.com/kingmoat/KingMoat-WAF/raw/main/deploy/install.sh | bash\n' >&2
        printf '\033[1;31m[error]\033[0m or:  bash install.sh [options]\n' >&2
        exit 1
    fi
    # A truncated pipe (download interrupted mid-stream) would otherwise run
    # as a partial installer. bash -n is best-effort: a cut landing exactly
    # on a top-level command boundary can still slip through, but the second
    # pass then fails on its own early steps.
    if ! bash -n "$_reexec" 2>/dev/null; then
        rm -f "$_reexec"
        err "piped script is truncated (download interrupted?) - re-run the install command"
    fi
    # Best effort: hand the second pass a terminal on stdin so the
    # interactive prompts can read real input when the pipe came from an
    # interactive session. Without a tty (CI, nested automation) this is
    # skipped and the interactive reads below fall back to their defaults
    # on EOF.
    { exec 0</dev/tty; } 2>/dev/null || true
    KINGMOAT_REEXEC="$_reexec" exec bash "$_reexec" "${_ORIG_ARGS[@]}"
fi

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------
if $UNINSTALL; then
    need_root
    # Prefer the install metadata written by a previous run of this script
    # (custom install dirs); fall back to the default location. The conf is
    # parsed with a strict two-key whitelist instead of being sourced - it
    # must never execute as root. Illegal values are skipped with a warning
    # and the default applies: uninstall must not be blocked by a corrupted
    # conf, and a missed (warned-about) dir beats a wrongly deleted one.
    INSTALL_DIR="/opt/kingmoat"
    if [[ -f /etc/kingmoat-install.conf ]]; then
        while IFS= read -r _conf_line; do
            _conf_key="${_conf_line%%=*}"
            _conf_val="${_conf_line#*=}"
            case "$_conf_key" in
                INSTALL_DIR|DATA_DIR) ;;
                *) continue ;;
            esac
            # Expect the exact quoted form the installer writes: KEY="value"
            _conf_val="${_conf_val%\"}"
            _conf_val="${_conf_val#\"}"
            case "$_conf_val" in
                /*) ;;
                *) warn "ignoring illegal value in /etc/kingmoat-install.conf for $_conf_key (not an absolute path)"; continue ;;
            esac
            case "$_conf_val" in
                *'"'*|*'$'*|*'`'*|*' '*) warn "ignoring illegal value in /etc/kingmoat-install.conf for $_conf_key (unsupported characters)"; continue ;;
            esac
            case "$_conf_key" in
                INSTALL_DIR) INSTALL_DIR="$_conf_val" ;;
                DATA_DIR)    [[ -z "$DATA_DIR" ]] && DATA_DIR="$_conf_val" ;;
            esac
        done < /etc/kingmoat-install.conf
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

PKG_NAME="kingmoat_${RELEASE_TAG}_linux_${PKG_ARCH}"
# Gitee asset naming convention (no dot in tag): tar.gz
ASSET_FILE="${PKG_NAME}.tar.gz"
DL_URL_GITEE="${GITEE_DL}/${RELEASE_TAG}/${ASSET_FILE}"
DL_URL_GITHUB="${GITHUB_DL}/${RELEASE_TAG}/${ASSET_FILE}"

DL_SOURCE=""
download_release() {
    log "downloading $ASSET_FILE ..."
    if curl -fSL --max-time 300 --retry 2 -o "$TMPDIR_INSTALL/$ASSET_FILE" "$DL_URL_GITEE" 2>/dev/null; then
        log "downloaded from Gitee ✓"
        DL_SOURCE="gitee"
        return 0
    fi
    log "Gitee download failed, trying GitHub ..."
    if curl -fSL --max-time 300 --retry 2 -o "$TMPDIR_INSTALL/$ASSET_FILE" "$DL_URL_GITHUB" 2>/dev/null; then
        log "downloaded from GitHub ✓"
        DL_SOURCE="github"
        return 0
    fi
    err "download failed from both mirrors. Check network or use --version to pin a valid tag."
}
download_release

# Verify checksum (fail-closed: refuse to install unverified binaries).
# Fetch checksums.txt from the mirror that served the binary first, then
# fall back to the other one - a single unreachable mirror must not break
# an otherwise complete download.
log "verifying checksum ..."
case "$DL_SOURCE" in
    github) _cs_urls=("${GITHUB_DL}/${RELEASE_TAG}/checksums.txt" "${GITEE_DL}/${RELEASE_TAG}/checksums.txt") ;;
    *)      _cs_urls=("${GITEE_DL}/${RELEASE_TAG}/checksums.txt" "${GITHUB_DL}/${RELEASE_TAG}/checksums.txt") ;;
esac
if ! curl -fSL --max-time 30 -o "$TMPDIR_INSTALL/checksums.txt" "${_cs_urls[0]}" 2>/dev/null; then
    log "checksums.txt unavailable from the primary mirror, trying the other one ..."
    if ! curl -fSL --max-time 30 -o "$TMPDIR_INSTALL/checksums.txt" "${_cs_urls[1]}" 2>/dev/null; then
        err "checksums.txt not available for $RELEASE_TAG - refusing to install unverified binaries"
    fi
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
    # The archive wraps contents in a top-level package directory (e.g.
    # kingmoat_v0.7.5-beta_linux_amd64/). Search exactly one level below the
    # temp dir: -mindepth 1 keeps the temp dir itself (named kingmoat-install.*)
    # from matching its own kingmoat* prefix, -maxdepth 1 matches the wrapper
    # our packager produces without descending further.
    SUBDIR=$(find "$TMPDIR_INSTALL" -mindepth 1 -maxdepth 1 -type d -name 'kingmoat*' | head -1)
    if [[ -n "$SUBDIR" ]]; then
        mv "$SUBDIR"/* "$TMPDIR_INSTALL/"
    fi
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
    # Every prompt tolerates EOF (piped install without a terminal): read
    # keeps the default and the install continues unattended.
    echo ""
    printf '\033[1;36m── 安装目录 ──\033[0m\n'
    read -rp "安装目录 [$INSTALL_DIR]: " INPUT_INSTALL || true
    [[ -n "${INPUT_INSTALL:-}" ]] && INSTALL_DIR="$INPUT_INSTALL"

    printf '\033[1;36m── 数据目录 ──\033[0m\n'
    echo "数据目录存放 SQLite 配置库、审计日志与证书（必须是本机磁盘，不能是 NFS/SMB）。"
    DEFAULT_DATA="/var/lib/kingmoat"
    read -rp "数据目录 [$DEFAULT_DATA]: " INPUT_DATA || true
    if [[ -n "${INPUT_DATA:-}" ]]; then
        DATA_DIR="$INPUT_DATA"
    elif [[ -z "$DATA_DIR" ]]; then
        DATA_DIR="$DEFAULT_DATA"
    fi

    printf '\033[1;36m── 控制台端口 ──\033[0m\n'
    read -rp "控制台 HTTPS 端口 [$CONSOLE_PORT_DEFAULT]: " INPUT_PORT || true
    [[ -n "${INPUT_PORT:-}" ]] && CONSOLE_PORT_DEFAULT="$INPUT_PORT"
fi

# Validate data dir is on a local filesystem (create it first so the
# detection can resolve the mount instead of silently failing on a
# missing path)
DATA_DIR="${DATA_DIR:-/var/lib/kingmoat}"
mkdir -p "$DATA_DIR" 2>/dev/null || true
_fs_type=""
if command -v findmnt &>/dev/null; then
    # FSTYPE lookup is authoritative; no more guessing from device-name
    # strings in df output.
    _fs_type=$(findmnt -n -o FSTYPE --target "$DATA_DIR" 2>/dev/null || true)
    case "$_fs_type" in
        nfs*|cifs*|smb*|fuse*) err "data dir is on a network filesystem ($_fs_type) - SQLite requires a local disk" ;;
    esac
elif df -T "$DATA_DIR" 2>/dev/null | tail -1 | grep -qE 'nfs|cifs|smbfs|fuse'; then
    # Fallback for minimal/container environments without findmnt.
    err "data dir is on a network filesystem - SQLite requires a local disk"
fi

# Path sanity for the systemd sandbox: ProtectHome=true hides /home and
# /root entirely, and spaces cannot be carried through ExecStart safely.
for _p in "$INSTALL_DIR" "$DATA_DIR"; do
    case "$_p" in
        *' '*|*'"'*|*'$'*|*'`'*) err "path contains unsupported characters (space, double quote, \$ or backtick): $_p" ;;
        /home|/home/*|/root|/root/*) err "path under /home or /root is hidden by systemd ProtectHome=true: $_p" ;;
    esac
done

# Console port sanity before it lands in ExecStart. Leading zeros are
# rejected outright (they used to slip past this check via octal arithmetic
# errors) and the range check forces decimal evaluation with 10#.
if ! [[ "$CONSOLE_PORT_DEFAULT" =~ ^(0|[1-9][0-9]{0,4})$ ]] || (( 10#$CONSOLE_PORT_DEFAULT < 1 || 10#$CONSOLE_PORT_DEFAULT > 65535 )); then
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
    # From here until the service is confirmed running again, any exit path
    # (error, signal) must try to bring it back - see cleanup().
    SERVICE_STOPPED=true
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
    # The upgrade's stop/start window is closed; from here on a failure no
    # longer needs service recovery in cleanup().
    SERVICE_STOPPED=false
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
