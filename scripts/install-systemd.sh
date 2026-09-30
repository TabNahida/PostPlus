#!/usr/bin/env bash
# Install a completed PostPlus server as a system service.
set -euo pipefail

usage() {
    cat <<'HELP'
Usage: install-systemd.sh [--install-dir DIR] [--working-dir DIR] [--config FILE]
                          [--user USER] [--dry-run]

Install and start postplus.service for an already configured server.
Run from an unpacked Linux release with sudo. The default install and working
directories are the release directory containing this script; the default
configuration is WORKING-DIR/config/postplus.json. Source builds can specify
--install-dir for the binary directory and --working-dir for the repository.

The service runs as the configuration file owner, including root. If that owner
cannot be resolved, it uses SUDO_USER or the invoking user. Use --user to
override it; the selected user must already be able to access the config.
--dry-run prints the proposed unit without writing files or calling systemctl.
Stop any manually running PostPlus instance before installing the service.
HELP
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
install_dir=$script_dir/..
working_dir=
config_path=
service_user=
dry_run=false

while (($#)); do
    case $1 in
        --install-dir|--working-dir|--config|--user)
            option=$1
            (($# >= 2)) || die "$option requires a value; use --help"
            [[ -n $2 ]] || die "$option requires a nonempty value"
            case $option in
                --install-dir) install_dir=$2 ;;
                --working-dir) working_dir=$2 ;;
                --config) config_path=$2 ;;
                --user) service_user=$2 ;;
            esac
            shift 2
            ;;
        --dry-run) dry_run=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1; use --help" ;;
    esac
done

[[ $(uname -s) == Linux ]] || die 'this installer requires Linux and systemd'
command -v realpath >/dev/null || die 'realpath is required'
command -v stat >/dev/null || die 'stat is required'

install_dir=$(realpath -e -- "$install_dir") || die "installation directory does not exist: $install_dir"
[[ -d $install_dir ]] || die "installation path is not a directory: $install_dir"
if [[ -z $working_dir ]]; then working_dir=$install_dir; fi
working_dir=$(realpath -e -- "$working_dir") || die "working directory does not exist: $working_dir"
[[ -d $working_dir ]] || die "working path is not a directory: $working_dir"
if [[ -z $config_path ]]; then config_path=$working_dir/config/postplus.json; fi
config_path=$(realpath -e -- "$config_path") || die "configuration does not exist: $config_path"
[[ -f $config_path && -r $config_path ]] || die "configuration must be a readable regular file: $config_path"

# The setup wizard writes this marker only after provisioning the administrator.
# The launcher will perform full JSON and credential validation at service start.
grep -Eq '"setup_complete"[[:space:]]*:[[:space:]]*true([[:space:],}]|$)' -- "$config_path" ||
    die "setup is not complete in $config_path; finish the browser setup first"
if grep -Eq '"setup_required"[[:space:]]*:[[:space:]]*true([[:space:],}]|$)' -- "$config_path"; then
    die "setup is required in $config_path; finish the browser setup first"
fi

for service in postplus postplus-admin postplus-auth postplus-storage postplus-filter \
               postplus-transfer postplus-delivery postplus-smtp postplus-pop3 postplus-imap postplus-web; do
    [[ -f $install_dir/$service && -x $install_dir/$service ]] ||
        die "missing executable $install_dir/$service; keep the complete release together"
done

if [[ -z $service_user ]]; then
    owner=$(stat -c '%U' -- "$config_path") || die 'cannot identify configuration owner'
    if [[ $owner != UNKNOWN ]] && id -u "$owner" >/dev/null 2>&1; then
        service_user=$owner
    elif [[ -n ${SUDO_USER:-} ]]; then
        service_user=$SUDO_USER
    else
        service_user=$(id -un)
    fi
fi
[[ $service_user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || die 'invalid service user name'
id -u "$service_user" >/dev/null 2>&1 || die "user does not exist: $service_user"

for value in "$install_dir" "$working_dir" "$config_path"; do
    [[ $value != *$'\n'* && $value != *$'\r'* ]] || die 'paths cannot contain line breaks'
done

if [[ $(id -u) == 0 ]] && command -v runuser >/dev/null; then
    for service in postplus postplus-admin postplus-auth postplus-storage postplus-filter \
                   postplus-transfer postplus-delivery postplus-smtp postplus-pop3 postplus-imap postplus-web; do
        runuser -u "$service_user" -- test -x "$install_dir/$service" ||
            die "$service_user cannot execute $install_dir/$service"
    done
    runuser -u "$service_user" -- test -r "$config_path" ||
        die "$service_user cannot read $config_path"
    runuser -u "$service_user" -- test -w "$(dirname -- "$config_path")" ||
        die "$service_user cannot write the configuration directory; settings updates require it"
fi

# systemd expands % specifiers in these settings. ExecStart also expands $vars.
# Quote each argument and escape both expansion syntaxes so unusual paths work.
unit_quote() {
    local escaped=${1//\\/\\\\}
    escaped=${escaped//\"/\\\"}
    escaped=${escaped//%/%%}
    printf '"%s"' "$escaped"
}
exec_quote() {
    local escaped=${1//\$/\$\$}
    unit_quote "$escaped"
}

unit_file=/etc/systemd/system/postplus.service
unit_content=$(cat <<EOF
# Managed by PostPlus install-systemd.sh; do not edit directly.
[Unit]
Description=PostPlus mail server
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
User=$service_user
WorkingDirectory=$(unit_quote "$working_dir")
ExecStart=$(exec_quote "$install_dir/postplus") --config $(exec_quote "$config_path")
Restart=on-failure
RestartSec=5s
KillMode=mixed
TimeoutStopSec=130s
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
)

if [[ -e $unit_file || -L $unit_file ]]; then
    [[ ! -L $unit_file && -f $unit_file ]] || die "refusing to replace $unit_file"
    IFS= read -r first_line < "$unit_file" || true
    [[ $first_line == '# Managed by PostPlus install-systemd.sh; do not edit directly.' ]] ||
        die "refusing to overwrite an unrelated unit: $unit_file"
fi

if $dry_run; then
    printf 'Would install %s and enable/start postplus.service as %s:\n\n%s\n' \
        "$unit_file" "$service_user" "$unit_content"
    exit 0
fi

[[ $(id -u) == 0 ]] || die 'installation needs root privileges; rerun with sudo or use --dry-run'
command -v systemctl >/dev/null || die 'systemctl is required; install on a systemd host'
[[ -d /etc/systemd/system ]] || die 'systemd unit directory is missing: /etc/systemd/system'
loaded_unit=$(systemctl show -p FragmentPath --value postplus.service 2>/dev/null || true)
if [[ -n $loaded_unit && $loaded_unit != "$unit_file" ]]; then
    die "postplus.service is already provided by $loaded_unit; refusing to override it"
fi

temporary_unit=$(mktemp /etc/systemd/system/.postplus.service.XXXXXX)
trap 'rm -f -- "${temporary_unit:-}"' EXIT
printf '%s\n' "$unit_content" > "$temporary_unit"
chmod 0644 "$temporary_unit"
changed=false
if [[ ! -f $unit_file ]] || ! cmp -s -- "$temporary_unit" "$unit_file"; then
    mv -fT -- "$temporary_unit" "$unit_file"
    temporary_unit=
    changed=true
fi

if ! systemctl daemon-reload; then
    die 'systemctl daemon-reload failed; inspect the unit and retry'
fi
if $changed && systemctl is-active --quiet postplus.service; then
    if ! systemctl restart postplus.service; then
        die 'restart failed; inspect: systemctl status postplus.service; journalctl -u postplus.service -e'
    fi
fi
if ! systemctl enable --now postplus.service; then
    die 'enable/start failed; stop any manually running PostPlus, then inspect: systemctl status postplus.service; journalctl -u postplus.service -e'
fi
printf 'Installed and enabled postplus.service; startup requested. Check: systemctl status postplus.service\n'
