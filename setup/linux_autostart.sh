#!/usr/bin/env bash
set -euo pipefail

# Configure HUSTAutologin as a systemd user service.
#
# Usage:
#   bash setup/linux_autostart.sh
#   bash setup/linux_autostart.sh --run-now
#
# The password is written to a user-only config file under
# ~/.config/hust-autologin. Keep that file permission at 600.
# Runtime logs are written to the project logs/ directory.

task_name="hust-autologin"
interval="30"
startup_delay="20"
run_now="0"
verbose_log="0"
user_id="${CAMPUS_USER_ID:-}"
password="${CAMPUS_PASSWORD:-}"
python_bin="${PYTHON_BIN:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --task-name)
            task_name="$2"
            shift 2
            ;;
        --user-id)
            user_id="$2"
            shift 2
            ;;
        --password)
            password="$2"
            shift 2
            ;;
        --python)
            python_bin="$2"
            shift 2
            ;;
        --interval)
            interval="$2"
            shift 2
            ;;
        --startup-delay)
            startup_delay="$2"
            shift 2
            ;;
        --verbose)
            verbose_log="1"
            shift
            ;;
        --run-now)
            run_now="1"
            shift
            ;;
        -h|--help)
            cat <<'EOF'
Usage:
  bash setup/linux_autostart.sh [options]

Options:
  --task-name NAME        systemd service name, default hust-autologin
  --user-id ID           campus user id; prompts when omitted
  --password PASSWORD    campus password; prompts silently when omitted; may remain in shell history
  --python PATH          python executable, default python3 from PATH
  --interval SECONDS     guard interval, default 30
  --startup-delay SEC    startup delay, default 20
  --verbose              enable verbose autologin logs
  --run-now              start the service immediately after enabling it
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$python_bin" ]]; then
    if command -v python3 >/dev/null 2>&1; then
        python_bin="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        python_bin="$(command -v python)"
    else
        echo "Python not found. Install python3 or pass --python /path/to/python." >&2
        exit 1
    fi
fi

if ! "$python_bin" -c "import requests" >/dev/null 2>&1; then
    echo "Warning: Python dependency 'requests' is missing." >&2
    echo "Install it with: $python_bin -m pip install requests" >&2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tool_dir="$(cd -- "$script_dir/.." && pwd)"
login_script="$tool_dir/HUSTAutologin.py"

if [[ ! -f "$login_script" ]]; then
    echo "Cannot find HUSTAutologin.py beside this setup script." >&2
    exit 1
fi

if [[ -z "$user_id" ]]; then
    read -r -p "Campus user id: " user_id
fi
if [[ -z "$user_id" ]]; then
    echo "Campus user id is required." >&2
    exit 1
fi

if [[ -z "$password" ]]; then
    read -r -s -p "Campus password: " password
    echo
fi
if [[ -z "$password" ]]; then
    echo "Campus password is required." >&2
    exit 1
fi

shell_quote() {
    local escaped
    escaped="$(printf "%s" "$1" | sed "s/'/'\\\\''/g")"
    printf "'%s'" "$escaped"
}

config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
config_dir="$config_home/hust-autologin"
log_dir="$tool_dir/logs"
env_file="$config_dir/env"
runner="$config_dir/run_autologin_linux.sh"
service_dir="$config_home/systemd/user"
service_file="$service_dir/${task_name}.service"

mkdir -p "$config_dir" "$log_dir" "$service_dir"
chmod 700 "$config_dir"

{
    printf "export CAMPUS_USER_ID=%s\n" "$(shell_quote "$user_id")"
    printf "export CAMPUS_PASSWORD=%s\n" "$(shell_quote "$password")"
    printf "export CAMPUS_LOG_DIR=%s\n" "$(shell_quote "$log_dir")"
} > "$env_file"
chmod 600 "$env_file"

verbose_arg=""
if [[ "$verbose_log" == "1" ]]; then
    verbose_arg=" --verbose"
fi

cat > "$runner" <<EOF
#!/usr/bin/env bash
set -euo pipefail
source $(shell_quote "$env_file")
exec $(shell_quote "$python_bin") $(shell_quote "$login_script") --loop --interval $(shell_quote "$interval") --startup-delay $(shell_quote "$startup_delay") --no-prompt$verbose_arg
EOF
chmod 700 "$runner"

cat > "$service_file" <<EOF
[Unit]
Description=HUST campus autologin
After=default.target

[Service]
Type=simple
WorkingDirectory=$tool_dir
ExecStart=/usr/bin/env bash $(shell_quote "$runner")
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
if [[ "$run_now" == "1" ]]; then
    systemctl --user enable "$task_name.service"
    if systemctl --user is-active --quiet "$task_name.service"; then
        systemctl --user restart "$task_name.service"
    else
        systemctl --user start "$task_name.service"
    fi
else
    systemctl --user enable "$task_name.service"
fi

echo "Configured systemd user service: $task_name.service"
echo "Runner: $runner"
echo "Logs: $log_dir"
echo "Check status with: systemctl --user status $task_name.service"
echo "If this machine should run it before login, run: sudo loginctl enable-linger $USER"
