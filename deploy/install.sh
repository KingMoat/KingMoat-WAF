#!/usr/bin/env bash
# ============================================================================
# KingMoat WAF — one-click install for Debian 12+ / Ubuntu 24.04+ / openEuler 22.03+
#
# Usage:
#   curl -fsSL https://gitee.com/kingmoat/KingMoat-WAF/raw/main/deploy/install.sh | bash
#   bash install.sh                       # interactive
#   bash install.sh --version v0.7.8-beta  # pin a version
#   bash install.sh --data-dir /opt/km    # non-interactive data dir
#   bash install.sh -y --http-port 80 --https-port 443 --console-port 8443
#   bash install.sh --uninstall           # remove everything
#
# What it does:
#   1. Detects distro and installs curl + tar + systemd (if missing)
#   2. Downloads the latest (or pinned) release from Gitee (fallback: GitHub)
#   3. Asks the user for install/data dirs and data-plane/console ports
#      (port occupancy on the host is checked with ss before the service starts)
#   4. Generates a minimal config.json and installs a systemd unit
#   5. Starts the service and verifies the console responds
#   6. Legacy migration: a pre-kingmoatwaf install (v0.7.9-beta and earlier:
#      /etc/kingmoat-install.conf, kingmoat.service, /opt/kingmoat,
#      /var/lib/kingmoat) is detected and migrated to the new layout
#      automatically - data is copied and verified, the old directories are
#      renamed aside (never deleted), any pending upgrade intent is dropped
#      (it would otherwise trigger a false-failure rollback on first boot)
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
# The script's own source URLs: the piped-install guard re-downloads a fresh
# copy instead of trusting the unread tail of stdin (see the guard below).
readonly INSTALLER_URL_PRIMARY="https://gitee.com/kingmoat/KingMoat-WAF/raw/main/deploy/install.sh"
readonly INSTALLER_URL_FALLBACK="https://raw.githubusercontent.com/kingmoat/KingMoat-WAF/main/deploy/install.sh"
# Port defaults, deliberately NOT readonly: the interactive prompts, the
# --*-port options and the upgrade-path parsing below may all replace them
# (assigning a readonly var aborts under set -e). 80/443 are privileged
# ports; the unit runs as root with CAP_NET_BIND_SERVICE so they bind fine.
CONSOLE_PORT_DEFAULT="8443"
DATA_PORT_DEFAULT="80"         # data plane HTTP  (config listen_http)
DATA_HTTPS_PORT_DEFAULT="443"  # data plane HTTPS (config listen_https)

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

# Parse an install-record file with a strict two-key whitelist instead of
# sourcing it - it must never execute as root. Sets _conf_install/_conf_data
# (empty when absent or illegal; illegal values are warned about). Used for
# both the new (/etc/kingmoatwaf-install.conf) and the legacy
# (/etc/kingmoat-install.conf) record layout.
parse_install_conf() {
    local file="$1"
    _conf_install=""
    _conf_data=""
    local line key val
    while IFS= read -r line; do
        key="${line%%=*}"
        val="${line#*=}"
        case "$key" in
            INSTALL_DIR|DATA_DIR) ;;
            *) continue ;;
        esac
        # Expect the exact quoted form the installer writes: KEY="value"
        val="${val%\"}"
        val="${val#\"}"
        case "$val" in
            /*) ;;
            *) warn "ignoring illegal value in $file for $key (not an absolute path)"; continue ;;
        esac
        case "$val" in
            *'"'*|*'$'*|*'`'*|*' '*) warn "ignoring illegal value in $file for $key (unsupported characters)"; continue ;;
        esac
        case "$key" in
            INSTALL_DIR) _conf_install="$val" ;;
            DATA_DIR)    _conf_data="$val" ;;
        esac
    done < "$file"
}

# ---------------------------------------------------------------------------
# Legacy install detection (v0.7.9-beta and earlier layout)
# ---------------------------------------------------------------------------
# A legacy install is identified by its install record or its systemd unit
# (either implies the other once, but manual installs only have the unit).
# Old paths serve as fallbacks when the record is missing or points nowhere.
# Detection runs before the directory prompts so the prompts can announce
# the pending migration; nothing is modified here.
readonly LEGACY_CONF="/etc/kingmoat-install.conf"
readonly LEGACY_UNIT="/etc/systemd/system/kingmoat.service"
readonly LEGACY_DEFAULT_INSTALL="/opt/kingmoat"
readonly LEGACY_DEFAULT_DATA="/var/lib/kingmoat"
MIGRATE=false
OLD_INSTALL_DIR=""
OLD_DATA_DIR=""
# Whether a legacy /etc/kingmoat config dir exists (manual-install layout):
# checked at detection time because finalize_legacy_migration renames it
# aside before the summary banner is printed.
HAD_LEGACY_ETC=false

detect_legacy_install() {
    OLD_INSTALL_DIR="$LEGACY_DEFAULT_INSTALL"
    OLD_DATA_DIR="$LEGACY_DEFAULT_DATA"
    if [[ -f "$LEGACY_CONF" ]]; then
        parse_install_conf "$LEGACY_CONF"
        [[ -n "${_conf_install:-}" ]] && OLD_INSTALL_DIR="$_conf_install"
        [[ -n "${_conf_data:-}" ]] && OLD_DATA_DIR="$_conf_data"
    elif [[ ! -f "$LEGACY_UNIT" ]]; then
        return 1
    fi
    if [[ -d /etc/kingmoat ]]; then
        HAD_LEGACY_ETC=true
    fi
    # A record/unit pointing at dirs that do not exist is a stale leftover:
    # there is nothing to migrate, install fresh.
    [[ -d "$OLD_INSTALL_DIR" || -d "$OLD_DATA_DIR" ]] || return 1
    MIGRATE=true
    return 0
}

# Set to true after an upgrade/migration has stopped a running service and
# back to false once the service is confirmed running again; cleanup() reads
# it to best-effort restart the service on any aborted exit path (no
# rollback).
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
        # Upgrade/migration aborted between "systemctl stop" and a verified
        # running service: best-effort restart, no version rollback. A new
        # binary that cannot start is left failed on purpose - the original
        # error must stay visible.
        # Two-level attempt: the new kingmoatwaf unit when present (upgrade,
        # or a migration that already got that far - its data dir is complete
        # by then), otherwise the legacy kingmoat unit (an aborted early
        # migration: the legacy unit and data dir are both untouched). A
        # failing start blocks until systemd gives up before falling through
        # to the legacy unit - slow but the safe direction.
        warn "attempting to restart the service after aborted run ..."
        systemctl start kingmoatwaf.service 2>/dev/null \
            || systemctl start kingmoat.service 2>/dev/null \
            || true
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

# Explicit --*-port markers: the upgrade path below seeds the port defaults
# from the old config.json/systemd unit; an explicitly passed port must win
# over those seeds instead of being silently overwritten by them.
DATA_PORT_SET=false
DATA_HTTPS_PORT_SET=false
CONSOLE_PORT_SET=false

# Parsing consumes "$@" via shift; keep the original list so the piped
# re-exec guard below can hand the exact same options to the second pass
# (parsing is idempotent and side-effect free).
_ORIG_ARGS=("$@")

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)      [[ $# -ge 2 ]] || err "--version requires a value"; PINNED_VERSION="$2"; shift 2 ;;
        --data-dir)     [[ $# -ge 2 ]] || err "--data-dir requires a value"; DATA_DIR="$2"; shift 2 ;;
        --http-port)    [[ $# -ge 2 ]] || err "--http-port requires a value"; DATA_PORT_DEFAULT="$2"; DATA_PORT_SET=true; shift 2 ;;
        --https-port)   [[ $# -ge 2 ]] || err "--https-port requires a value"; DATA_HTTPS_PORT_DEFAULT="$2"; DATA_HTTPS_PORT_SET=true; shift 2 ;;
        --console-port) [[ $# -ge 2 ]] || err "--console-port requires a value"; CONSOLE_PORT_DEFAULT="$2"; CONSOLE_PORT_SET=true; shift 2 ;;
        --uninstall)    UNINSTALL=true; shift ;;
        -y|--yes)       NONINTERACTIVE=true; shift ;;
        *)              err "unknown option: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Re-exec guard: when piped in (curl | bash), the interactive "read" prompts
# below would swallow script lines, so the second pass runs from a temp file
# instead. KINGMOAT_REEXEC carries the copy's path into the second pass: it
# keeps this guard from re-triggering and lets the EXIT trap remove the copy.
#
# The copy must NOT be built by "cat > file": bash reads the piped script
# through its own buffer, so at this point fd0 only yields the unread tail of
# the script - a partial copy that crashed real installs with undefined
# helpers. The copy is re-downloaded from the fixed source URL instead,
# which is independent of how much of stdin bash has already buffered.
#
# The guard only applies to runs that actually consume stdin interactively:
# -y (non-interactive) and --uninstall never read from stdin, so they
# proceed even on a non-tty fd0 (CI, `ssh host 'bash install.sh -y'`).
# ---------------------------------------------------------------------------
# Only trust a caller-provided KINGMOAT_REEXEC that looks like what this
# script itself sets for the second pass: an absolute path under
# /tmp/kingmoatwaf-install.* pointing at an existing file. Anything else is
# dropped so a forged value can neither bypass the guard nor leak into the
# cleanup rm below.
KINGMOAT_REEXEC="${KINGMOAT_REEXEC:-}"
if [[ -n "$KINGMOAT_REEXEC" && ( $KINGMOAT_REEXEC != /* || $KINGMOAT_REEXEC != /tmp/kingmoatwaf-install.* || ! -f $KINGMOAT_REEXEC ) ]]; then
    KINGMOAT_REEXEC=""
fi
if [[ ! -t 0 && -z "$KINGMOAT_REEXEC" && $NONINTERACTIVE == false && $UNINSTALL == false ]]; then
    _reexec="$(mktemp /tmp/kingmoatwaf-install.XXXXXX)"
    # Re-download a complete copy (see the rationale above); fail over to the
    # mirror URL when the primary is unreachable.
    if ! curl -fsSL --max-time 60 -o "$_reexec" "$INSTALLER_URL_PRIMARY" \
       && ! curl -fsSL --max-time 60 -o "$_reexec" "$INSTALLER_URL_FALLBACK"; then
        rm -f "$_reexec"
        err "cannot fetch the installer for re-exec; run instead: curl -fsSL $INSTALLER_URL_PRIMARY -o install.sh && sudo bash install.sh"
    fi
    if [[ ! -s "$_reexec" ]]; then
        rm -f "$_reexec"
        err "fetched installer is empty; check network and re-run the install command"
    fi
    # Integrity check on the downloaded copy (a proxy/CDN serving a truncated
    # or corrupt body would otherwise fail cryptically in the second pass).
    if ! bash -n "$_reexec" 2>/dev/null; then
        rm -f "$_reexec"
        err "fetched installer failed a syntax check - re-run the install command"
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
    # (custom install dirs); fall back to the legacy pre-rename record
    # (/etc/kingmoat-install.conf) so old installs uninstall cleanly too.
    # The conf is parsed with a strict two-key whitelist instead of being
    # sourced - it must never execute as root. Illegal values are skipped
    # with a warning and the default applies: uninstall must not be blocked
    # by a corrupted conf, and a missed (warned-about) dir beats a wrongly
    # deleted one.
    INSTALL_DIR="/opt/kingmoatwaf"
    for _rec in /etc/kingmoatwaf-install.conf /etc/kingmoat-install.conf; do
        [[ -f "$_rec" ]] || continue
        parse_install_conf "$_rec"
        [[ -n "${_conf_install:-}" ]] && INSTALL_DIR="$_conf_install"
        [[ -n "${_conf_data:-}" && -z "$DATA_DIR" ]] && DATA_DIR="$_conf_data"
        break
    done
    log "stopping and disabling kingmoatwaf.service (and any legacy kingmoat.service) ..."
    systemctl disable --now kingmoatwaf.service 2>/dev/null || true
    systemctl disable --now kingmoat.service 2>/dev/null || true
    rm -f /etc/systemd/system/kingmoatwaf.service /etc/systemd/system/kingmoat.service \
        /etc/kingmoatwaf-install.conf /etc/kingmoat-install.conf
    systemctl daemon-reload
    rm -f /usr/local/bin/kingmoatwaf /usr/local/bin/kmwafctl
    rm -rf "$INSTALL_DIR"
    warn "data dir NOT removed. Remove manually if desired:"
    warn "  rm -rf ${DATA_DIR:-/var/lib/kingmoatwaf}"
    warn "renamed-aside migration backups (*.migrated-*) are NOT removed either."
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
TMPDIR_INSTALL=$(mktemp -d /tmp/kingmoatwaf-install.XXXXXX)

PKG_NAME="kingmoatwaf_${RELEASE_TAG}_linux_${PKG_ARCH}"
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
# Escape regex metacharacters in the (self-produced) asset name so the
# pattern matches literally instead of interpreting dots as wildcards.
ESCAPED_ASSET=$(printf '%s' "${ASSET_FILE}" | sed 's/[][\.|^$()*+?{}]/\\&/g')
EXPECTED=$(grep -E "(^|[[:space:]])${ESCAPED_ASSET}([[:space:]]|$)" "$TMPDIR_INSTALL/checksums.txt" | awk '{print $1}' | head -1)
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
if [[ ! -f "$TMPDIR_INSTALL/kingmoatwaf" ]]; then
    # The archive wraps contents in a top-level package directory (e.g.
    # kingmoatwaf_v0.7.10-beta_linux_amd64/). Search exactly one level below
    # the temp dir: -mindepth 1 keeps the temp dir itself (named
    # kingmoatwaf-install.*) from matching its own kingmoatwaf* prefix,
    # -maxdepth 1 matches the wrapper our packager produces without
    # descending further.
    SUBDIR=$(find "$TMPDIR_INSTALL" -mindepth 1 -maxdepth 1 -type d -name 'kingmoatwaf*' | head -1)
    if [[ -n "$SUBDIR" ]]; then
        mv "$SUBDIR"/* "$TMPDIR_INSTALL/"
    fi
fi
[[ -f "$TMPDIR_INSTALL/kingmoatwaf" ]] || err "kingmoatwaf binary not found in archive"
log "extracted ✓"
chmod +x "$TMPDIR_INSTALL/kingmoatwaf"
[[ -f "$TMPDIR_INSTALL/kmwafctl" ]] && chmod +x "$TMPDIR_INSTALL/kmwafctl"

# ---------------------------------------------------------------------------
# Interactive directory selection
# ---------------------------------------------------------------------------
# Detect a legacy (pre-kingmoatwaf) install BEFORE the prompts so they can
# announce the pending migration. Purely informational here - nothing is
# modified until after the ports are settled and the old service is stopped.
detect_legacy_install || true

INSTALL_DIR="/opt/kingmoatwaf"
if [[ $NONINTERACTIVE == false ]]; then
    # Every prompt tolerates EOF (piped install without a terminal): read
    # keeps the default and the install continues unattended.
    echo ""
    if [[ $MIGRATE == true ]]; then
        printf '\033[1;36m── 检测到旧版安装 ──\033[0m\n'
        echo "发现旧版布局：安装目录 $OLD_INSTALL_DIR、数据目录 $OLD_DATA_DIR（记录/服务 kingmoat.service）。"
        echo "回车采用下方默认新目录即可自动迁移：数据目录复制并校验后切换，旧目录改名保留（*.migrated-<时间戳>，不删除）。"
        echo "迁移会先停旧服务 kingmoat.service，待新服务 kingmoatwaf 验证正常后再清理旧 unit。"
    fi
    printf '\033[1;36m── 安装目录 ──\033[0m\n'
    read -rp "安装目录 [$INSTALL_DIR]: " INPUT_INSTALL || true
    [[ -n "${INPUT_INSTALL:-}" ]] && INSTALL_DIR="$INPUT_INSTALL"

    printf '\033[1;36m── 数据目录 ──\033[0m\n'
    echo "数据目录存放 SQLite 配置库、审计日志与证书（必须是本机磁盘，不能是 NFS/SMB）。"
    DEFAULT_DATA="/var/lib/kingmoatwaf"
    read -rp "数据目录 [$DEFAULT_DATA]: " INPUT_DATA || true
    if [[ -n "${INPUT_DATA:-}" ]]; then
        DATA_DIR="$INPUT_DATA"
    elif [[ -z "$DATA_DIR" ]]; then
        DATA_DIR="$DEFAULT_DATA"
    fi
fi

# Validate data dir is on a local filesystem (create it first so the
# detection can resolve the mount instead of silently failing on a
# missing path)
DATA_DIR="${DATA_DIR:-/var/lib/kingmoatwaf}"
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

# ---------------------------------------------------------------------------
# Upgrade path: preserve the ports already in place.
#   - data plane ports live in config.json; that file is only generated when
#     absent, so an upgrade keeps it as-is (a NEW port typed below is patched
#     into the two listen_* fields instead of regenerating the file)
#   - the console port used to live in the systemd unit only, which IS
#     rewritten on every run - its previous value is parsed from the existing
#     unit's -console-addr and seeded as the prompt default, so a plain
#     re-run never resets a port the user has changed back to the install
#     default; since the EnvironmentFile migration (console.env) the env
#     file is authoritative instead and is seeded from the parsed unit port
#   - seeding never overrides an explicit --http-port / --https-port /
#     --console-port: the command line wins over the old config/unit/env
# ---------------------------------------------------------------------------
CONFIG_FILE="$DATA_DIR/config.json"
OLD_HTTP_ADDR=""
OLD_HTTPS_ADDR=""
_old_console=""
# Effective config source for port seeding: the NEW data dir first (plain
# upgrade), then the legacy data dir and finally the legacy /etc/kingmoat
# seed (manual-install layout keeps config.json there) when migrating.
CONFIG_SRC=""
if [[ -f "$CONFIG_FILE" ]]; then
    CONFIG_SRC="$CONFIG_FILE"
elif [[ $MIGRATE == true && -n "$OLD_DATA_DIR" && "$OLD_DATA_DIR" != "$DATA_DIR" && -f "$OLD_DATA_DIR/config.json" ]]; then
    CONFIG_SRC="$OLD_DATA_DIR/config.json"
elif [[ $MIGRATE == true && -f /etc/kingmoat/config.json ]]; then
    CONFIG_SRC="/etc/kingmoat/config.json"
fi
if [[ -n "$CONFIG_SRC" ]]; then
    OLD_HTTP_ADDR=$(grep -oP '"listen_http"\s*:\s*"\K[^"]*' "$CONFIG_SRC" | head -1 || true)
    OLD_HTTPS_ADDR=$(grep -oP '"listen_https"\s*:\s*"\K[^"]*' "$CONFIG_SRC" | head -1 || true)
fi
FINAL_HTTP_ADDR="$OLD_HTTP_ADDR"
FINAL_HTTPS_ADDR="$OLD_HTTPS_ADDR"
if [[ -z "$FINAL_HTTP_ADDR" ]]; then
    FINAL_HTTP_ADDR="0.0.0.0:${DATA_PORT_DEFAULT}"
elif [[ $DATA_PORT_SET == false ]]; then
    # carry the existing port forward as the effective default (an explicit
    # --http-port takes precedence over the old config)
    _p="${FINAL_HTTP_ADDR##*:}"
    [[ "$_p" =~ ^[0-9]{1,5}$ ]] && DATA_PORT_DEFAULT="$_p"
fi
if [[ -z "$FINAL_HTTPS_ADDR" ]]; then
    if [[ -n "$CONFIG_SRC" ]]; then
        FINAL_HTTPS_ADDR=""           # upgrade from an older install: keep the HTTPS data plane off unless a port is entered below
        [[ $DATA_HTTPS_PORT_SET == false ]] && DATA_HTTPS_PORT_DEFAULT=""
    else
        FINAL_HTTPS_ADDR="0.0.0.0:${DATA_HTTPS_PORT_DEFAULT}"
    fi
elif [[ $DATA_HTTPS_PORT_SET == false ]]; then
    _p="${FINAL_HTTPS_ADDR##*:}"
    [[ "$_p" =~ ^[0-9]{1,5}$ ]] && DATA_HTTPS_PORT_DEFAULT="$_p"
fi
# Console port resolution precedence (an explicit --console-port always
# wins over everything below):
#   1. the existing console.env EnvironmentFile (migration already done) -
#      the unit no longer carries the real port there, so the env file is
#      authoritative;
#   2. the previous unit's -console-addr (pre-EnvironmentFile installs) -
#      the port is carried into the freshly written console.env so the unit
#      switches to the EnvironmentFile mechanism without a port change.
CONSOLE_ENV_FILE="$DATA_DIR/console.env"
if [[ -f "$CONSOLE_ENV_FILE" && $CONSOLE_PORT_SET == false ]]; then
    _env_console=$(sed -n 's/^CONSOLE_PORT=\([0-9]\{1,5\}\).*/\1/p' "$CONSOLE_ENV_FILE" | head -1 || true)
    if [[ -n "$_env_console" ]]; then
        _old_console="$_env_console"
        CONSOLE_PORT_DEFAULT="$_env_console"
    fi
fi
# Migration: the port the legacy console.env carries wins over the old unit
# (same precedence as above - the env file is the newer mechanism).
if [[ -z "$_old_console" && $MIGRATE == true && -n "$OLD_DATA_DIR" && "$OLD_DATA_DIR" != "$DATA_DIR" && -f "$OLD_DATA_DIR/console.env" && $CONSOLE_PORT_SET == false ]]; then
    _old_console=$(sed -n 's/^CONSOLE_PORT=\([0-9]\{1,5\}\).*/\1/p' "$OLD_DATA_DIR/console.env" | head -1 || true)
    if [[ -n "$_old_console" ]]; then
        CONSOLE_PORT_DEFAULT="$_old_console"
    fi
fi
# Last resort: parse the -console-addr out of the existing unit. The legacy
# kingmoat.service covers migrations, kingmoatwaf.service covers pre-envfile
# installs on the new layout (the current unit carries the literal
# \${CONSOLE_PORT} there, which the numeric match below simply ignores).
if [[ -z "$_old_console" && $CONSOLE_PORT_SET == false ]]; then
    for _unit in /etc/systemd/system/kingmoat.service /etc/systemd/system/kingmoatwaf.service; do
        [[ -f "$_unit" ]] || continue
        _old_console=$(sed -n 's/.*-console-addr [^[:space:]]*:\([0-9]\{1,5\}\).*/\1/p' "$_unit" | head -1 || true)
        if [[ -n "$_old_console" ]]; then
            CONSOLE_PORT_DEFAULT="$_old_console"
            break
        fi
    done
fi

# ---------------------------------------------------------------------------
# Interactive port selection
# ---------------------------------------------------------------------------
if [[ $NONINTERACTIVE == false ]]; then
    printf '\033[1;36m── 数据面端口 ──\033[0m\n'
    echo "默认监听 0.0.0.0:80(HTTP) / 0.0.0.0:443(HTTPS)。80/443 为特权端口，本脚本以 root 部署并已授予 CAP_NET_BIND_SERVICE，可直接绑定。"
    echo "安装前会用 ss 检测端口是否已被宿主机上其他进程监听，被占用时会要求重选。"
    if [[ $DATA_PORT_SET == true ]]; then
        echo "已通过 --http-port 指定端口 ${DATA_PORT_DEFAULT}，直接回车生效（输入其他值可覆盖）。"
    elif [[ -n "$OLD_HTTP_ADDR" ]]; then
        echo "检测到现有配置 listen_http=${OLD_HTTP_ADDR}，直接回车保留。"
    fi
    read -rp "数据面 HTTP 端口 [${DATA_PORT_DEFAULT}]: " INPUT_HTTP_PORT || true
    if [[ -n "${INPUT_HTTP_PORT:-}" ]]; then
        DATA_PORT_DEFAULT="$INPUT_HTTP_PORT"
    fi
    if [[ -n "$OLD_HTTPS_ADDR" ]]; then
        if [[ $DATA_HTTPS_PORT_SET == true ]]; then
            echo "已通过 --https-port 指定端口 ${DATA_HTTPS_PORT_DEFAULT}，直接回车生效（输入其他值可覆盖）。"
        else
            echo "检测到现有配置 listen_https=${OLD_HTTPS_ADDR}，直接回车保留。"
        fi
        read -rp "数据面 HTTPS 端口 [${DATA_HTTPS_PORT_DEFAULT}]: " INPUT_HTTPS_PORT || true
        if [[ -n "${INPUT_HTTPS_PORT:-}" ]]; then
            DATA_HTTPS_PORT_DEFAULT="$INPUT_HTTPS_PORT"
        fi
    elif [[ -z "$CONFIG_SRC" || $DATA_HTTPS_PORT_SET == true ]]; then
        # Fresh install (or an explicit --https-port): Enter enables the
        # HTTPS data plane on the shown default, matching the -y path and
        # the banner above.
        read -rp "数据面 HTTPS 端口 [0.0.0.0:${DATA_HTTPS_PORT_DEFAULT}，直接回车=启用]: " INPUT_HTTPS_PORT || true
        if [[ -n "${INPUT_HTTPS_PORT:-}" ]]; then
            DATA_HTTPS_PORT_DEFAULT="$INPUT_HTTPS_PORT"
        fi
    else
        # Upgrade with the HTTPS data plane currently off and no explicit
        # --https-port: Enter keeps it off; typing a port turns it on.
        read -rp "数据面 HTTPS 端口 [直接回车=保持未启用，输入端口=启用]: " INPUT_HTTPS_PORT || true
        DATA_HTTPS_PORT_DEFAULT="${INPUT_HTTPS_PORT:-}"
    fi

    printf '\033[1;36m── 控制台端口 ──\033[0m\n'
    if [[ $CONSOLE_PORT_SET == true ]]; then
        echo "已通过 --console-port 指定端口 ${CONSOLE_PORT_DEFAULT}，直接回车生效（输入其他值可覆盖）。"
    elif [[ -n "$_old_console" ]]; then
        echo "检测到现有控制台端口 ${_old_console}（升级时直接回车保留）。"
    fi
    read -rp "控制台 HTTPS 端口 [$CONSOLE_PORT_DEFAULT]: " INPUT_PORT || true
    [[ -n "${INPUT_PORT:-}" ]] && CONSOLE_PORT_DEFAULT="$INPUT_PORT"
fi

# Port sanity (format/range) for all three ports before anything lands in
# config.json or the unit. Leading zeros are rejected outright (they used to
# slip past this check via octal arithmetic errors) and the range check
# forces decimal evaluation with 10#. Occupancy/exclusivity is checked
# later, after the old service has been stopped (see below).
validate_port() {
    local label="$1" p="$2"
    [[ -z "$p" ]] && return 0
    if ! [[ "$p" =~ ^(0|[1-9][0-9]{0,4})$ ]] || (( 10#$p < 1 || 10#$p > 65535 )); then
        err "invalid $label port: $p (need 1-65535)"
    fi
}
validate_port "HTTP data-plane" "$DATA_PORT_DEFAULT"
validate_port "HTTPS data-plane" "$DATA_HTTPS_PORT_DEFAULT"
validate_port "console" "$CONSOLE_PORT_DEFAULT"

# ---------------------------------------------------------------------------
# Install files
# ---------------------------------------------------------------------------
# Upgrades/migration: stop the running service before replacing anything
# (an in-place cp over a live executable fails with ETXTBSY and set -e
# aborts midway). The legacy kingmoat.service is only stopped for a
# migration; its unit file is left in place until the new service is
# verified, so an aborted run can always restart it (see cleanup()).
if systemctl cat kingmoatwaf.service &>/dev/null && systemctl is-active --quiet kingmoatwaf.service; then
    log "stopping existing kingmoatwaf.service for upgrade ..."
    systemctl stop kingmoatwaf.service
    # From here until the service is confirmed running again, any exit path
    # (error, signal) must try to bring it back - see cleanup().
    SERVICE_STOPPED=true
elif [[ $MIGRATE == true ]] && systemctl is-active --quiet kingmoat.service 2>/dev/null; then
    log "stopping legacy kingmoat.service for migration ..."
    systemctl stop kingmoat.service
    SERVICE_STOPPED=true
fi

# ---------------------------------------------------------------------------
# Legacy data migration (pre-kingmoatwaf installs)
# ---------------------------------------------------------------------------
# Runs AFTER the old service is stopped (no live writes while copying) and
# BEFORE anything destructive happens. Deliberately conservative strategy:
#   - copy (cp -a) the legacy data dir into the new one, then verify file
#     count and byte total; the legacy dir is NOT touched by the copy, so a
#     failed/aborted copy leaves the old install fully intact and restartable
#     (the cleanup hook restarts it). A same-filesystem mv would be cheaper
#     but is NOT used: once moved, any failure past that point could no
#     longer restart the old service against its data.
#   - verification compares file count and du -sb byte totals between the
#     legacy dir and the copy
#   - any pending upgrade intent is dropped UNCONDITIONALLY: after the
#     layout migration the L1/L2 self-heal (kmwafctl upgrade-rollback /
#     startup check) would compare the NEW kingmoatwaf binary against the
#     recorded intent, judge the migration a failed upgrade and roll the
#     service back to a legacy kingmoat backup. intent.json only carries
#     target_version/target_sha256/backup/timestamp - nothing the migration
#     needs, everything the self-heal must not see.
#   - renaming the legacy dirs aside (*.migrated-<ts>) happens only AFTER
#     the new service is verified running (finalize_legacy_migration);
#     until then the legacy install stays startable at its original paths.
migrate_legacy_data() {
    if [[ "$OLD_DATA_DIR" != "$DATA_DIR" ]]; then
        log "migrating legacy data: $OLD_DATA_DIR -> $DATA_DIR"
        # Make sure the legacy service is really down before the copy: any
        # live write during the copy (WAL checkpoint, daily archive) breaks
        # the strict verification below. The main flow stops it earlier;
        # this is a re-entry/idempotency backstop (e.g. the user restarted
        # the legacy service after an earlier aborted attempt).
        if systemctl is-active --quiet kingmoat.service 2>/dev/null; then
            systemctl stop kingmoat.service
            sleep 1
            log "legacy kingmoat.service was still active; stopped it before copying"
        fi
        # Re-entry guard: a previously aborted migration attempt leaves the
        # target populated (e.g. WAL files the crashed new service wrote),
        # which would make the strict count/byte verification below fail on
        # every retry. The target is created and managed by this script, so
        # start each attempt from a clean target.
        if [[ -e "$DATA_DIR" ]]; then
            case "$DATA_DIR/" in
                /|/var/|/var/lib/|/etc/|/opt/|/usr/|/bin/|/sbin/|/boot/|/dev/|/proc/|/sys/|/run/|/home/|/root/|/tmp/)
                    err "refusing to wipe unsafe data dir: $DATA_DIR" ;;
            esac
            rm -rf "$DATA_DIR"
            log "cleared previous target $DATA_DIR (leftover from an earlier aborted attempt)"
        fi
        if ! cp -a "$OLD_DATA_DIR/." "$DATA_DIR/"; then
            warn "a partial copy may exist at $DATA_DIR; remove it manually if desired (rm -rf)"
            err "data migration copy failed; aborting - legacy install untouched, restart it manually with: sudo systemctl start kingmoat.service"
        fi
        local src_files dst_files src_bytes dst_bytes
        src_files=$(find "$OLD_DATA_DIR" -type f | wc -l)
        dst_files=$(find "$DATA_DIR" -type f | wc -l)
        src_bytes=$(du -sb "$OLD_DATA_DIR" | awk '{print $1}')
        dst_bytes=$(du -sb "$DATA_DIR" | awk '{print $1}')
        if [[ "$src_files" != "$dst_files" || "$src_bytes" != "$dst_bytes" ]]; then
            warn "copy verification FAILED (files $src_files->$dst_files, bytes $src_bytes->$dst_bytes)"
            warn "a partial copy may exist at $DATA_DIR; remove it manually if desired (rm -rf)"
            err "data migration verification failed; aborting - legacy install untouched, restart it manually with: sudo systemctl start kingmoat.service"
        fi
        log "data migration verified ✓ ($src_files files, $src_bytes bytes)"
    else
        log "data dir unchanged ($DATA_DIR): the legacy install already targets it, no copy needed"
    fi
    if [[ -f "$DATA_DIR/upgrade/intent.json" ]]; then
        rm -f "$DATA_DIR/upgrade/intent.json"
        log "cleared $DATA_DIR/upgrade/intent.json (prevents false-failure rollback after the migration)"
    fi
    # Rewrite stale absolute paths inside the migrated config.json: a legacy
    # config may point audit_log_dir (or other files) at $OLD_DATA_DIR,
    # which the new unit's ReadWritePaths sandbox does not allow - SQLite
    # then fails with SQLITE_CANTOPEN and the service crash-loops. The
    # trailing-slash pattern cannot touch kingmoatwaf paths ("kingmoat/"
    # never matches inside "kingmoatwaf/").
    if [[ -n "$OLD_DATA_DIR" && "$OLD_DATA_DIR" != "$DATA_DIR" && -f "$DATA_DIR/config.json" ]]; then
        # Trailing-slash normalization (review item C8): an install record
        # carrying "dir/" made the "dir//" pattern never match and silently
        # skipped the rewrite. The MIGRATE/-f guard above keeps the raw
        # values; only the rewrite patterns normalize. Strip ALL trailing
        # slashes (review C5-②): "${v%/}" only removed one, so "dir//" vs
        # "dir" still differed after normalization.
        local sed_old="$OLD_DATA_DIR" sed_new="$DATA_DIR"
# Strip ALL trailing slashes: a single-character pattern with % or %%
# removes at most one, so "dir//" would survive as "dir/" and the rewrite
# pattern would silently never match again (verified with a live shell).
while [[ $sed_old == */ ]]; do sed_old=${sed_old%/}; done
while [[ $sed_new == */ ]]; do sed_new=${sed_new%/}; done
        # Same value after normalization (e.g. old="dir/" new="dir"): the
        # rewrite would be a no-op, so say so instead of claiming a rewrite
        # (review C5-①).
        if [[ "$sed_old" == "$sed_new" ]]; then
            log "config.json data dir unchanged after trailing-slash normalization ($sed_new): no rewrite needed"
        # Literal-metacharacter guard (review C5-③): the rewrite is a sed
        # s|||g over arbitrary config content. A path carrying sed/grep
        # metacharacters or the "|" delimiter would error or corrupt the
        # JSON, so only spellings that are inert in both tools are rewritten
        # in place; anything else degrades to an explicit manual hint.
        elif [[ "$sed_old$sed_new" == *[!A-Za-z0-9/._-]* ]]; then
            warn "data dir path contains sed/shell-special characters - not rewriting $DATA_DIR/config.json automatically; fix legacy paths manually (quote them for sed)"
        elif grep -qF "$sed_old/" "$DATA_DIR/config.json"; then
            sed -i "s|$sed_old/|$sed_new/|g" "$DATA_DIR/config.json"
            log "rewrote legacy $sed_old/ paths in $DATA_DIR/config.json"
        else
            log "no legacy $sed_old/ paths in $DATA_DIR/config.json - nothing to rewrite"
        fi
    fi
    # Same rewrite for the console config DB (kingmoat.db): the live config
    # lives in its `revisions` table and legacy revisions may still point
    # tls_cert/tls_key/custom-rule/GeoIP paths at $OLD_DATA_DIR, which makes
    # every console publish fail after the migration ("read tls_cert: open
    # /var/lib/kingmoat/..."). Runs in the same stopped-service window.
    if [[ -n "$OLD_DATA_DIR" && "$OLD_DATA_DIR" != "$DATA_DIR" && -f "$DATA_DIR/kingmoat.db" ]]; then
        rewrite_legacy_db_paths "$DATA_DIR/kingmoat.db" "$OLD_DATA_DIR" "$DATA_DIR"
    fi
    # Manual-install layout keeps the seed config under /etc/kingmoat; the
    # install.sh layout keeps it in the data dir - carry it over when the
    # migrated data dir has none. The legacy /etc/kingmoat/env is NOT
    # carried over: it belongs to the manual unit (see the summary banner
    # for what that means for KINGMOAT_ADMIN_HASH).
    if [[ -f /etc/kingmoat/config.json && ! -f "$DATA_DIR/config.json" ]]; then
        cp -a /etc/kingmoat/config.json "$DATA_DIR/config.json"
        log "carried legacy /etc/kingmoat/config.json into $DATA_DIR/config.json"
    fi
}

# ---------------------------------------------------------------------------
# Legacy console-DB path rewrite (upgrade migration helper)
# ---------------------------------------------------------------------------
# The live configuration is stored as JSON in the `revisions` table of the
# console config DB (kingmoat.db). Legacy revisions may reference site
# certificates, custom rule files or the GeoIP db under the OLD data dir;
# after the layout migration those files only exist under the new dir, so
# every console publish fails with "read tls_cert: open /var/lib/kingmoat/
# ..." until the rows are fixed. The rewrite runs inside the same
# stopped-service window as the config.json rewrite (legacy service down,
# new service not started yet) and applies the same trailing-slash-safe
# replacement ("kingmoat/" never matches inside "kingmoatwaf/", so already
# rewritten paths are untouched and re-runs are no-ops). Only "/" and plain
# letters are ever swapped, so the JSON stays valid without any escaping.
# A pending WAL is checkpointed before and after so the rewrite lands in
# the main DB file. It never aborts the install: a missing DB, a missing
# revisions table or missing tools degrade to a logged skip, or to a
# printed manual fix command marked "migration NOT completed".
_rewrite_db_paths_sqlite3() {
    local db="$1" old_dir="$2" new_dir="$3"
    # -init /dev/null: never read the user's ~/.sqliterc — a dotfile with
    # dot commands (e.g. ".headers on" / ".output") corrupts the captured
    # output and silently pushes the rewrite into the "NOT completed" branch
    # (review item C7).
    sqlite3 -batch -init /dev/null "$db" "PRAGMA wal_checkpoint(TRUNCATE);" &>/dev/null || true
    local has_revisions
    if ! has_revisions=$(sqlite3 -batch -init /dev/null "$db" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='revisions';"); then
        warn "cannot inspect $db with sqlite3 - legacy path rewrite skipped"
        return 1
    fi
    if [[ "$has_revisions" != "1" ]]; then
        log "$db has no revisions table - nothing to rewrite"
        return 0
    fi
    local changed
    if ! changed=$(sqlite3 -batch -init /dev/null "$db" "UPDATE revisions SET config = replace(config, '${old_dir}/', '${new_dir}/') WHERE instr(config, '${old_dir}/') > 0; SELECT changes();"); then
        return 1
    fi
    sqlite3 -batch -init /dev/null "$db" "PRAGMA wal_checkpoint(TRUNCATE);" &>/dev/null || true
    if [[ "$changed" =~ ^[0-9]+$ && "$changed" -gt 0 ]]; then
        log "rewrote legacy $old_dir/ paths in $db (revisions updated: $changed)"
    else
        log "no legacy $old_dir/ paths in $db revisions - nothing to rewrite"
    fi
    return 0
}

_rewrite_db_paths_python3() {
    local db="$1" old_dir="$2" new_dir="$3"
    local py_out
    if py_out=$(python3 - "$db" "$old_dir" "$new_dir" <<'PYEOF'
import sqlite3
import sys

db, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
prefix = old + "/"
con = sqlite3.connect(db)
try:
    cur = con.cursor()
    cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    if cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='revisions'").fetchone()[0] == 0:
        print("no revisions table in %s - nothing to rewrite" % db)
        sys.exit(0)
    cur.execute(
        "UPDATE revisions SET config = replace(config, ?, ?) WHERE instr(config, ?) > 0",
        (prefix, new + "/", prefix),
    )
    rows = cur.rowcount
    con.commit()
    cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    if rows > 0:
        print("rewrote legacy %s paths in %s (revisions updated: %d)" % (prefix, db, rows))
    else:
        print("no legacy %s paths in %s revisions - nothing to rewrite" % (prefix, db))
finally:
    con.close()
PYEOF
); then
        while IFS= read -r _pyline; do log "$_pyline"; done <<< "$py_out"
        return 0
    fi
    return 1
}

rewrite_legacy_db_paths() {
    local db="$1" old_dir="$2" new_dir="$3"
    # Trailing-slash normalization (review item C8, hardened per C5-②):
    # an install record with "dir/" made the "dir//" instr() pattern never
    # match - a silent no-op in every branch below (sqlite3, python3 and
    # the manual hint). Strip ALL trailing slashes so every consumer sees
    # the same spelling: a single-character pattern with % or %% removes at
    # most one slash, so "dir//" would survive as "dir/" (verified live).
    old_dir="${old_dir%/}"
    new_dir="${new_dir%/}"
    while [[ $old_dir == */ ]]; do old_dir=${old_dir%/}; done
    while [[ $new_dir == */ ]]; do new_dir=${new_dir%/}; done
    if [[ -z "$old_dir" || -z "$new_dir" ]]; then
        warn "empty data dir after trailing-slash normalization - not rewriting $db"
        return 0
    fi
    if [[ ! -f "$db" ]]; then
        log "no console config DB at $db - skipping legacy path rewrite"
        return 0
    fi
    case "$old_dir$new_dir" in
        *"'"*)
            warn "data dir path contains a single quote - not rewriting $db automatically"
            return 0
            ;;
    esac
    local manual_hint="sqlite3 -batch -init /dev/null \"$db\" \"UPDATE revisions SET config = replace(config, '$old_dir/', '$new_dir/') WHERE instr(config, '$old_dir/') > 0;\""
    if command -v sqlite3 &>/dev/null; then
        if ! _rewrite_db_paths_sqlite3 "$db" "$old_dir" "$new_dir"; then
            warn "sqlite3 rewrite of $db FAILED - migration NOT completed automatically; fix manually if console publishes fail:"
            warn "  $manual_hint"
        fi
    elif command -v python3 &>/dev/null; then
        if ! _rewrite_db_paths_python3 "$db" "$old_dir" "$new_dir"; then
            warn "python3 rewrite of $db FAILED - migration NOT completed automatically; fix manually if console publishes fail:"
            warn "  $manual_hint"
        fi
    else
        warn "neither sqlite3 nor python3 available - console DB $db migration NOT completed automatically; run manually if console publishes fail:"
        warn "  $manual_hint"
    fi
    return 0
}

# Tear down the legacy layout AFTER the new service is verified running.
# Everything here is a rename-aside or a removal of now-redundant unit/record
# files - never a data deletion. A failing step degrades to a warning (the
# new layout is already live; aborting here would only mislead), and the
# leftover is reported for manual cleanup.
finalize_legacy_migration() {
    local ts
    ts=$(date +%Y%m%d%H%M%S)
    if [[ "$OLD_DATA_DIR" != "$DATA_DIR" && -d "$OLD_DATA_DIR" ]]; then
        if mv "$OLD_DATA_DIR" "${OLD_DATA_DIR}.migrated-${ts}"; then
            log "legacy data dir preserved as ${OLD_DATA_DIR}.migrated-${ts}"
        else
            warn "could not rename legacy data dir $OLD_DATA_DIR aside - rename it manually once the new layout is confirmed good"
        fi
    fi
    if [[ "$OLD_INSTALL_DIR" != "$INSTALL_DIR" && -d "$OLD_INSTALL_DIR" ]]; then
        if mv "$OLD_INSTALL_DIR" "${OLD_INSTALL_DIR}.migrated-${ts}"; then
            log "legacy install dir (binaries, kingmoat.bak-* upgrade backups) preserved as ${OLD_INSTALL_DIR}.migrated-${ts}"
        else
            warn "could not rename legacy install dir $OLD_INSTALL_DIR aside - rename it manually once the new layout is confirmed good"
        fi
    fi
    if [[ -d /etc/kingmoat ]]; then
        if mv /etc/kingmoat "/etc/kingmoat.migrated-${ts}"; then
            log "legacy config dir /etc/kingmoat preserved as /etc/kingmoat.migrated-${ts}"
        else
            warn "could not rename legacy config dir /etc/kingmoat aside - rename it manually once the new layout is confirmed good"
        fi
    fi
    if [[ -f "$LEGACY_UNIT" ]]; then
        systemctl disable kingmoat.service 2>/dev/null || true
        rm -f "$LEGACY_UNIT"
        systemctl daemon-reload
        log "removed legacy kingmoat.service unit"
    fi
    if [[ -f "$LEGACY_CONF" ]]; then
        if mv "$LEGACY_CONF" "${LEGACY_CONF}.migrated-${ts}"; then
            log "legacy install record preserved as ${LEGACY_CONF}.migrated-${ts}"
        else
            warn "could not rename legacy install record $LEGACY_CONF aside - remove it manually once the new layout is confirmed good"
        fi
    fi
}
if [[ $MIGRATE == true ]]; then
    migrate_legacy_data
fi

# ---------------------------------------------------------------------------
# Port occupancy & exclusivity
# ---------------------------------------------------------------------------
# Deliberately checked AFTER the old service has been stopped: during an
# upgrade the running kingmoatwaf itself holds the very ports we are about to
# re-use, so checking earlier would flag our own service as a squatter.
# ss reports listeners on the whole host - that is the point: what matters
# is whether any OTHER process on the host would keep the port from binding.
if ! command -v ss &>/dev/null; then
    warn "ss not found - port occupancy cannot be checked; an occupied port will make the service fail to start"
fi

port_in_use() {
    local port="$1"
    command -v ss &>/dev/null || return 1
    ss -nHtln 2>/dev/null | awk -v p="$port" '{ n = split($4, a, ":"); if (a[n] == p) found = 1 } END { if (found) exit 0; exit 1 }'
}

# Loop until the port is free on the host and distinct from the ports in
# $others (space-separated). Interactive runs get to re-pick; non-interactive
# runs get a hard error that names the --*-port overrides.
pick_port() {
    local label="$1" port="$2" others="$3" input
    while true; do
        if [[ " $others " == *" $port "* ]]; then
            if [[ $NONINTERACTIVE == true ]]; then
                err "$label port $port conflicts with another KingMoat port ($others). Pick three distinct ports with --http-port / --https-port / --console-port."
            fi
            warn "$label端口 $port 与其他 KingMoat 端口冲突（$others），请换一个端口。"
            read -rp "请重新输入 $label 端口 (1-65535): " input || input=""
            if [[ -z "$input" ]]; then
                err "no input received - re-run and pass --http-port / --https-port / --console-port explicitly"
            fi
        elif port_in_use "$port"; then
            if [[ $NONINTERACTIVE == true ]]; then
                err "$label port $port is already in use on this host (checked with ss). Free the port or re-run and pick another one with --http-port / --https-port / --console-port."
            fi
            warn "$label端口 $port 已被宿主机上其他进程监听（ss 检测到）："
            ss -nHtlnp 2>/dev/null | awk -v p="$port" '{ n = split($4, a, ":"); if (a[n] == p) print "    " $0 }' || true
            warn "可停掉占用进程后重试，或输入其他端口；直接回车 = 忽略检测继续安装（服务可能启动失败）。"
            read -rp "请输入其他 $label 端口 (直接回车继续): " input || input=""
            if [[ -z "$input" ]]; then
                warn "按输入保留端口 $port 继续安装"
                break
            fi
        else
            break
        fi
        while ! [[ "$input" =~ ^(0|[1-9][0-9]{0,4})$ ]] || (( 10#$input < 1 || 10#$input > 65535 )); do
            warn "invalid port: $input (need 1-65535)"
            read -rp "请重新输入 $label 端口 (1-65535): " input || input=""
            if [[ -z "$input" ]]; then
                err "no input received - re-run and pass --http-port / --https-port / --console-port explicitly"
            fi
        done
        port="$input"
    done
    PICK_PORT="$port"
}

pick_port "数据面 HTTP" "$DATA_PORT_DEFAULT" "$DATA_HTTPS_PORT_DEFAULT $CONSOLE_PORT_DEFAULT"
DATA_PORT_DEFAULT="$PICK_PORT"
if [[ -n "$DATA_HTTPS_PORT_DEFAULT" ]]; then
    pick_port "数据面 HTTPS" "$DATA_HTTPS_PORT_DEFAULT" "$DATA_PORT_DEFAULT $CONSOLE_PORT_DEFAULT"
    DATA_HTTPS_PORT_DEFAULT="$PICK_PORT"
fi
pick_port "控制台" "$CONSOLE_PORT_DEFAULT" "$DATA_PORT_DEFAULT $DATA_HTTPS_PORT_DEFAULT"
CONSOLE_PORT_DEFAULT="$PICK_PORT"

# ---------------------------------------------------------------------------
# Console port EnvironmentFile (read by the unit's EnvironmentFile= below)
# ---------------------------------------------------------------------------
# ExecStart carries -console-addr 0.0.0.0:${CONSOLE_PORT} (expanded by systemd
# at start, NOT by this script), so the running service can move the console
# to a new port at runtime: the settings page rewrites this file and restarts
# the unit (the unit file itself is read-only under ProtectSystem=strict,
# while the data dir stays writable and the restart is a dbus IPC).
# Fresh installs write the port chosen above; upgrades write the port
# carried over from console.env or parsed from the previous unit (see the
# upgrade-path section), preserving it across the migration.
log "writing console environment file ..."
printf 'CONSOLE_PORT=%s\n' "$CONSOLE_PORT_DEFAULT" > "$CONSOLE_ENV_FILE"
chmod 600 "$CONSOLE_ENV_FILE"

log "installing to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR/logs" "$DATA_DIR/archive"
cp "$TMPDIR_INSTALL/kingmoatwaf" "$INSTALL_DIR/kingmoatwaf"
[[ -f "$TMPDIR_INSTALL/kmwafctl" ]]          && cp "$TMPDIR_INSTALL/kmwafctl"          "$INSTALL_DIR/kmwafctl"
[[ -f "$TMPDIR_INSTALL/README.md" ]]         && cp "$TMPDIR_INSTALL/README.md"         "$INSTALL_DIR/"
[[ -f "$TMPDIR_INSTALL/LICENSE" ]]           && cp "$TMPDIR_INSTALL/LICENSE"           "$INSTALL_DIR/"
[[ -f "$TMPDIR_INSTALL/NOTICE" ]]            && cp "$TMPDIR_INSTALL/NOTICE"            "$INSTALL_DIR/"
[[ -f "$TMPDIR_INSTALL/THIRD-PARTY-LICENSES" ]] && cp "$TMPDIR_INSTALL/THIRD-PARTY-LICENSES" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/kingmoatwaf"
[[ -f "$INSTALL_DIR/kmwafctl" ]] && chmod +x "$INSTALL_DIR/kmwafctl"

# Expose both binaries on the default PATH so the CLI can be used without
# the install-dir prefix; re-linked on every run so upgrades stay current.
ln -sf "$INSTALL_DIR/kingmoatwaf" /usr/local/bin/kingmoatwaf
[[ -f "$INSTALL_DIR/kmwafctl" ]] && ln -sf "$INSTALL_DIR/kmwafctl" /usr/local/bin/kmwafctl

# ---------------------------------------------------------------------------
# Generate config.json (fresh install) / patch listen_* fields (upgrade)
# ---------------------------------------------------------------------------
# Final listen addresses are assembled here, after occupancy re-picking: an
# upgrade keeps its existing bind address (e.g. 127.0.0.1) and only swaps
# the port; a fresh install listens on 0.0.0.0.
if [[ -n "$OLD_HTTP_ADDR" ]]; then
    FINAL_HTTP_ADDR="${OLD_HTTP_ADDR%:*}:${DATA_PORT_DEFAULT}"
else
    FINAL_HTTP_ADDR="0.0.0.0:${DATA_PORT_DEFAULT}"
fi
if [[ -n "$DATA_HTTPS_PORT_DEFAULT" ]]; then
    if [[ -n "$OLD_HTTPS_ADDR" ]]; then
        FINAL_HTTPS_ADDR="${OLD_HTTPS_ADDR%:*}:${DATA_HTTPS_PORT_DEFAULT}"
    else
        FINAL_HTTPS_ADDR="0.0.0.0:${DATA_HTTPS_PORT_DEFAULT}"
    fi
else
    FINAL_HTTPS_ADDR=""
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    log "generating $CONFIG_FILE ..."
    cat > "$CONFIG_FILE" <<JSONEOF
{
  "listen_http": "${FINAL_HTTP_ADDR}",
  "listen_https": "${FINAL_HTTPS_ADDR}",
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
else
    # Upgrade with a port the user explicitly changed: patch just the two
    # listen_* fields in place; every other byte of the seed config stays.
    if [[ "$FINAL_HTTP_ADDR" != "$OLD_HTTP_ADDR" ]]; then
        log "updating listen_http in $CONFIG_FILE: $OLD_HTTP_ADDR -> $FINAL_HTTP_ADDR"
        case "$FINAL_HTTP_ADDR" in *'&'*|*\\*|*'|'*) err "listen address contains unsupported characters: $FINAL_HTTP_ADDR" ;; esac
        sed -i "s|\"listen_http\"[[:space:]]*:[[:space:]]*\"[^\"]*\"|\"listen_http\": \"${FINAL_HTTP_ADDR}\"|" "$CONFIG_FILE"
        grep -qF "\"listen_http\": \"${FINAL_HTTP_ADDR}\"" "$CONFIG_FILE" || err "failed to patch listen_http in $CONFIG_FILE - edit it manually, then re-run"
    fi
    if [[ -n "$FINAL_HTTPS_ADDR" && "$FINAL_HTTPS_ADDR" != "$OLD_HTTPS_ADDR" ]]; then
        log "updating listen_https in $CONFIG_FILE: ${OLD_HTTPS_ADDR:-<unset>} -> $FINAL_HTTPS_ADDR"
        case "$FINAL_HTTPS_ADDR" in *'&'*|*\\*|*'|'*) err "listen address contains unsupported characters: $FINAL_HTTPS_ADDR" ;; esac
        sed -i "s|\"listen_https\"[[:space:]]*:[[:space:]]*\"[^\"]*\"|\"listen_https\": \"${FINAL_HTTPS_ADDR}\"|" "$CONFIG_FILE"
        grep -qF "\"listen_https\": \"${FINAL_HTTPS_ADDR}\"" "$CONFIG_FILE" || err "failed to patch listen_https in $CONFIG_FILE - edit it manually, then re-run"
    fi
fi

# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------
# Rewritten on every run (fresh install AND upgrade). The console port comes
# from the EnvironmentFile (${DATA_DIR}/console.env, written above): upgrades
# carry the previous port over (parsed from console.env or the old unit), so
# a re-run preserves a port the user changed instead of resetting it to the
# install default. Data-plane ports are not part of the unit; they live in
# config.json. \${CONSOLE_PORT} below is expanded by systemd from the env
# file, not by this script.
log "installing systemd unit ..."
cat > /etc/systemd/system/kingmoatwaf.service <<UNIT
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
StateDirectory=kingmoatwaf
ConfigurationDirectory=kingmoatwaf
ReadWritePaths=${DATA_DIR} ${INSTALL_DIR}
WorkingDirectory=${DATA_DIR}
# Console port (CONSOLE_PORT) lives in the EnvironmentFile so the running
# service can move the console to a new port at runtime (settings page:
# rewrite the file + systemctl restart; the unit file itself stays read-only
# under ProtectSystem=strict).
EnvironmentFile=${DATA_DIR}/console.env
# Optional admin-password anchor (KINGMOAT_ADMIN_HASH), written by admins to
# /etc/kingmoatwaf/env; leading "-" keeps startup tolerant when absent.
EnvironmentFile=-/etc/kingmoatwaf/env
# Self-healing rollback for interrupted online upgrades: compares the
# running binary against the recorded upgrade intent and restores the
# backup if the new binary failed to boot. The command itself never
# fails (exit 0 when no intent / intent satisfied / files missing), and
# the leading "-" makes systemd ignore its exit code even if the binary
# itself is missing - startup must never be blocked by this hook.
ExecStartPre="-${INSTALL_DIR}/kmwafctl" upgrade-rollback -data-dir "${DATA_DIR}"
ExecStart="${INSTALL_DIR}/kingmoatwaf" -config "${CONFIG_FILE}" -console-addr 0.0.0.0:\${CONSOLE_PORT} -console-db "${DATA_DIR}/kingmoat.db"
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
log "starting kingmoatwaf.service ..."
systemctl enable --now kingmoatwaf.service
sleep 2

if systemctl is-active --quiet kingmoatwaf.service; then
    log "service is running ✓"
    # The upgrade's stop/start window is closed; from here on a failure no
    # longer needs service recovery in cleanup().
    SERVICE_STOPPED=false
else
    err "service failed to start. Check: journalctl -u kingmoatwaf -n 30"
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
# The new service is verified running: only now is the legacy layout torn
# down (rename-aside + unit/record removal) - an aborted run before this
# point could always restart the legacy install (see cleanup()).
if [[ $MIGRATE == true ]]; then
    finalize_legacy_migration
fi

echo ""
printf '\033[1;32m════════════════════════════════════════════════\033[0m\n'
printf '\033[1;32m KingMoat WAF installed successfully!\033[0m\n'
printf '\033[1;32m════════════════════════════════════════════════\033[0m\n'
echo ""
if [[ $MIGRATE == true ]]; then
    echo "  Migration: legacy data $OLD_DATA_DIR -> $DATA_DIR (copied and verified)"
    echo "             legacy dirs/record renamed aside as *.migrated-* (kept, never deleted;"
    echo "             remove them manually once the new layout is confirmed good)"
    echo "             pending upgrade intent cleared - old kingmoat backups will NOT auto-rollback"
    if [[ $HAD_LEGACY_ETC == true ]]; then
        echo "             NOTE: legacy /etc/kingmoat/env (KINGMOAT_ADMIN_HASH etc.) is not carried;"
        echo "             reset the admin password with: ${INSTALL_DIR}/kmwafctl reset-password"
    fi
    echo ""
fi
_host_ip=$(hostname -I | awk '{print $1}')
if [[ -n "$DATA_HTTPS_PORT_DEFAULT" ]]; then
    echo "  Data plane: http://${_host_ip}:${DATA_PORT_DEFAULT} / https://${_host_ip}:${DATA_HTTPS_PORT_DEFAULT}"
else
    echo "  Data plane: http://${_host_ip}:${DATA_PORT_DEFAULT}  (HTTPS data plane is off)"
fi
echo "  Console:  https://${_host_ip}:${CONSOLE_PORT_DEFAULT}"
echo "            https://127.0.0.1:${CONSOLE_PORT_DEFAULT}  (local, self-signed cert)"
echo "  Account:  kmadmin / KingMoat@2026  (change password at first login!)"
echo "  Config:   $CONFIG_FILE"
echo "  Data:     $DATA_DIR"
echo "  Logs:     journalctl -u kingmoatwaf -f"
echo ""
echo "  Useful commands:"
echo "    systemctl status kingmoatwaf"
echo "    systemctl restart kingmoatwaf"
echo "    kmwafctl status                      # service, ports, console URL (on PATH)"
echo "    kmwafctl hash-password -password '...'"
echo ""

# Persist install locations for uninstall / future upgrades
cat > /etc/kingmoatwaf-install.conf <<META
INSTALL_DIR="$INSTALL_DIR"
DATA_DIR="$DATA_DIR"
META
chmod 600 /etc/kingmoatwaf-install.conf
