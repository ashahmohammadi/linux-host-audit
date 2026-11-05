# System level diagnosis and fixes: clock, disk, memory, kernel limits.

fx_mount_of() { df -P "$1" 2>/dev/null | awk 'NR == 2 { print $NF }'; }
fx_bytes() { awk -v b="${1:-0}" 'BEGIN { split("B KiB MiB GiB TiB", u, " "); i = 1
    while (b >= 1024 && i < 5) { b /= 1024; i++ } printf "%.1f %s", b, u[i] }'; }
fx_top_memory() {
    # Added up per program: 160 php-fpm workers are one memory user, not 160.
    ps -eo rss=,comm= 2>/dev/null | clean | awk '{ m[$2] += $1; n[$2]++ }
        END { for (p in m) printf "%d %d %s\n", m[p], n[p], p }' | sort -rn | head -n "${1:-5}" |
        awk '{ printf "%s%s %.1f GiB", (NR > 1 ? ", " : ""), $3, $1 / 1048576; if ($2 > 1) printf " (%s processes)", $2 }'
}

# Persists a kernel setting in its own file, so it is easy to find and to remove.
fx_sysctl() {
    local key=$1 value=$2 file=/etc/sysctl.d/90-linux-host-audit.conf old
    old=$(sysctl -n "$key" 2>/dev/null) || return 1
    fx_backup "$file" || return 1
    { grep -v "^$key " "$file" 2>/dev/null; printf '%s = %s\n' "$key" "$value"; } > "$file.lha-new" || return 1
    mv -f "$file.lha-new" "$file" || return 1
    fx_quote sysctl -w "$key=$old"
    fx_undo "$REPLY"
    fx_run sysctl -w "$key=$value"
}

dx_clock_unsynced() {
    local state
    state=$(timedatectl show -p NTP --value 2>/dev/null)
    FX_CAUSE="Time sync is ${state:-unknown}, and the clock is not synchronized."
    if [[ -n $H_CONTAINER ]]; then
        FX_MODE=guide FX_CAUSE='Containers use the clock of their host.'
        FX_STEPS=('Fix time sync on the host, not inside this container.')
    elif [[ $state == no ]]; then
        FX_MODE=auto FX_RISK=low
        FX_PLAN=('Turn on time sync: timedatectl set-ntp true')
    else
        FX_CAUSE='Time sync is on, but no time server has answered yet.'
        FX_STEPS=('Check that UDP port 123 can leave this server.' 'With chrony: chronyc sources' 'With systemd-timesyncd, systemd 239 or newer: timedatectl timesync-status')
    fi
}
ap_clock_unsynced() {
    fx_undo 'timedatectl set-ntp false'
    fx_run timedatectl set-ntp true
}
ck_clock_unsynced() { [[ $(timedatectl show -p NTP --value 2>/dev/null) == yes ]]; }

# Measures what can go without touching anything a person made. Sets FX_CLEAN_* in bytes.
fx_measure_clean() {
    local mnt=$1 size
    FX_CLEAN_JOURNAL=0 FX_CLEAN_PKG=0 FX_CLEAN_LOGS=0 FX_CLEAN_IMAGES=0
    if has journalctl && [[ $(fx_mount_of /var/log) == "$mnt" ]]; then
        size=$(du -sb /var/log/journal 2>/dev/null | awk '{ print $1 }')
        if [[ $size =~ ^[0-9]+$ ]] && ((size > 209715200)); then FX_CLEAN_JOURNAL=$((size - 209715200)); fi
    fi
    if [[ $(fx_mount_of /var/cache) == "$mnt" ]]; then
        FX_CLEAN_PKG=$(du -sbc /var/cache/apt/archives /var/cache/dnf /var/cache/yum 2>/dev/null | awk 'END { print $1 + 0 }')
    fi
    if [[ $(fx_mount_of /var/log) == "$mnt" ]]; then
        FX_CLEAN_LOGS=$(find /var/log -xdev -type f -name '*.gz' -mtime +14 -printf '%s\n' 2>/dev/null | awk '{ n += $1 } END { print n + 0 }')
    fi
    if has docker && [[ $(fx_mount_of /var/lib/docker) == "$mnt" ]]; then
        size=$(run_t 15 docker system df --format '{{.Type}} {{.Reclaimable}}' 2>/dev/null | awk '/^Images/ { print $2 }')
        [[ -z $size ]] || FX_CLEAN_IMAGES=$(run_t 8 docker images -f dangling=true -q 2>/dev/null | wc -l | tr -d ' ')
    fi
    FX_CLEAN_TOTAL=$((FX_CLEAN_JOURNAL + FX_CLEAN_PKG + FX_CLEAN_LOGS))
}

dx_disk_full() {
    local mnt=${1:-/} big
    big=$(run_t 30 du -xk --max-depth=2 "$mnt" 2>/dev/null | sort -rn | sed -n '2,6p' | clean |
        awk '{ printf "%s%s (%.1f GiB)", (NR > 1 ? ", " : ""), $2, $1 / 1048576 }')
    FX_CAUSE="Biggest folders on $mnt: ${big:-could not measure in time}."
    fx_measure_clean "$mnt"
    FX_STEPS=("du -xh $mnt --max-depth=3 | sort -h | tail -20" 'Files still open by a program keep their space: lsof +L1 | head')
    if ((FX_CLEAN_TOTAL + FX_CLEAN_IMAGES * 104857600 < 104857600)); then
        FX_CAUSE+=' Safe cleanup would free too little, so the space is in your own data.'
        FX_STEPS+=('Decide what to move or delete, or grow the disk.')
        return 0
    fi
    FX_MODE=auto FX_RISK=low FX_UNDOABLE=no FX_PLAN=()
    ((FX_CLEAN_JOURNAL == 0)) || FX_PLAN+=("Shrink system journal to 200 MiB: frees $(fx_bytes "$FX_CLEAN_JOURNAL")")
    ((FX_CLEAN_PKG == 0)) || FX_PLAN+=("Clear the package download cache: frees $(fx_bytes "$FX_CLEAN_PKG")")
    ((FX_CLEAN_LOGS == 0)) || FX_PLAN+=("Delete compressed logs older than 14 days: frees $(fx_bytes "$FX_CLEAN_LOGS")")
    ((FX_CLEAN_IMAGES == 0)) || FX_PLAN+=("Remove $FX_CLEAN_IMAGES unused untagged Docker images")
    FX_PLAN+=('Touches no site, database, upload or home folder.')
    FX_DISK_BEFORE=$(df -Pk "$mnt" | awk 'NR == 2 { print $3 }')
}
ap_disk_full() {
    ((FX_CLEAN_JOURNAL == 0)) || fx_run journalctl --vacuum-size=200M
    if ((FX_CLEAN_PKG > 0)); then
        if has apt-get; then fx_run apt-get clean
        elif has dnf; then fx_run dnf clean packages
        elif has yum; then fx_run yum clean packages
        fi
    fi
    ((FX_CLEAN_LOGS == 0)) || fx_run find /var/log -xdev -type f -name '*.gz' -mtime +14 -delete
    ((FX_CLEAN_IMAGES == 0)) || fx_run docker image prune -f
    return 0
}
ck_disk_full() {
    local now
    now=$(df -Pk "${1:-/}" | awk 'NR == 2 { print $3 }')
    ((now < FX_DISK_BEFORE))
}

dx_inodes_full() {
    local mnt=${1:-/} big
    big=$(run_t 30 du --inodes -x --max-depth=3 "$mnt" 2>/dev/null | sort -rn | sed -n '2,6p' | clean |
        awk '{ printf "%s%s (%s files)", (NR > 1 ? ", " : ""), $2, $1 }')
    FX_CAUSE="Folders with the most files: ${big:-could not measure in time}."
    FX_STEPS=('These are usually PHP sessions, mail queues or cache folders.'
        'Find what writes them before removing anything.'
        "du --inodes -x $mnt --max-depth=3 | sort -n | tail -20")
}

# Swap gives a memory-starved server room, and stops the OOM killer firing at the first spike.
FX_SWAPFILE=${LHA_FIX_SWAPFILE:-/swapfile}
fx_swap_possible() {
    local free
    [[ -z $H_CONTAINER ]] || return 1
    # Rollback removes this file, so it has to be one this fix made.
    [[ ! -e $FX_SWAPFILE ]] || return 1
    ((R_SWAP_TOTAL == 0)) || return 1
    case $(awk '$2 == "/" { print $3 }' /proc/mounts | tail -n 1) in ext*|xfs) ;; *) return 1 ;; esac
    free=$(df -Pk / | awk 'NR == 2 { print $4 }')
    ((free > 10485760))
}
fx_swap_plan() {
    FX_MODE=auto FX_RISK=medium
    FX_PLAN=('Create /swapfile (2 GiB), and enable it now and at boot.')
}
fx_swap_apply() {
    fx_backup /etc/fstab || return 1
    fx_undo 'rm -f /swapfile'
    fx_undo 'swapoff /swapfile'
    fx_run dd if=/dev/zero of=/swapfile bs=1M count=2048 || return 1
    fx_run chmod 600 /swapfile || return 1
    fx_run mkswap /swapfile || return 1
    fx_run swapon /swapfile || return 1
    { cat /etc/fstab; printf '/swapfile none swap sw 0 0\n'; } | fx_write /etc/fstab
}
fx_swap_check() { awk '$1 == "/swapfile" { found = 1 } END { exit !found }' /proc/swaps; }

fx_mysql_advice() {
    local pool ram=$((R_MEM_TOTAL * 1024))
    sql_find
    has "${SQL[0]}" || return 0
    pool=$(run_t 5 "${SQL[@]}" --connect-timeout=3 -NBe 'SELECT @@innodb_buffer_pool_size' 2>/dev/null)
    [[ $pool =~ ^[0-9]+$ ]] || return 0
    FX_CAUSE+=" MariaDB/MySQL buffer pool is $(fx_bytes "$pool") of $(fx_bytes "$ram") RAM."
    if ((pool * 100 / ram > 50)); then
        FX_STEPS+=("Lower the buffer pool, for example: SET GLOBAL innodb_buffer_pool_size = $((ram * 40 / 100));"
            'Then set the same value under [mysqld] so it survives a restart.')
    fi
}

dx_memory_low() {
    FX_CAUSE="Biggest users: $(fx_top_memory 5)."
    fx_mysql_advice
    FX_STEPS+=('Lower PHP-FPM pm.max_children if PHP is the top user.')
    tune_panel_steps fpm
    FX_STEPS+=('free -h' 'ps aux --sort=-rss | head')
    if fx_swap_possible; then fx_swap_plan; FX_CAUSE+=' This server has no swap.'; fi
}
ap_memory_low() { fx_swap_apply; }
ck_memory_low() { fx_swap_check; }
dx_oom_kills() {
    FX_CAUSE="Killed: ${1:-unknown}. Biggest users now: $(fx_top_memory 4)."
    fx_mysql_advice
    FX_STEPS+=('If php-fpm is a big user, lower pm.max_children.')
    tune_panel_steps fpm
    FX_STEPS+=('journalctl -k | grep -i "out of memory"' 'Add RAM if the numbers above already look reasonable.')
    if fx_swap_possible; then fx_swap_plan; FX_CAUSE+=' This server has no swap.'; fi
}
ap_oom_kills() { fx_swap_apply; }
ck_oom_kills() { fx_swap_check; }

dx_swap_high() {
    FX_CAUSE="Memory ran short at some point. Biggest users: $(fx_top_memory 4)."
    FX_STEPS=('Swap in use is only a problem if the server is actively swapping: vmstat 1 5, look at si and so.')
}

dx_file_limit() {
    local used max
    read -r used _ max < /proc/sys/fs/file-nr
    FX_CAUSE="$used of $max open file handles are in use."
    # Modern kernels default to the largest number there is, so doubling it would overflow.
    if ((max >= 4611686018427387904)); then
        FX_CAUSE='The system-wide limit is already unlimited, so the limit is on one program.'
        FX_STEPS=('Find the program near its own limit: linux-host-audit.sh --tune' 'Raise LimitNOFILE in its service unit.')
        return 0
    fi
    FX_MODE=auto FX_RISK=low FX_NEW_VALUE=$((max * 2))
    FX_PLAN=("Raise fs.file-max to $FX_NEW_VALUE (kernel setting, kept across reboots)")
}
ap_file_limit() { fx_sysctl fs.file-max "$FX_NEW_VALUE"; }
ck_file_limit() { [[ $(sysctl -n fs.file-max) == "$FX_NEW_VALUE" ]]; }

dx_conntrack_full() {
    local used max
    read -r used < /proc/sys/net/netfilter/nf_conntrack_count
    read -r max < /proc/sys/net/netfilter/nf_conntrack_max
    FX_CAUSE="$used of $max tracked connections are in use. New connections are being dropped."
    FX_MODE=auto FX_RISK=low FX_NEW_VALUE=$((max * 2))
    FX_PLAN=("Raise nf_conntrack_max to $FX_NEW_VALUE. It uses slightly more kernel memory.")
    FX_STEPS=('If traffic is abnormal, this may be an attack: ss -s')
}
ap_conntrack_full() { fx_sysctl net.netfilter.nf_conntrack_max "$FX_NEW_VALUE"; }
ck_conntrack_full() { [[ $(sysctl -n net.netfilter.nf_conntrack_max) == "$FX_NEW_VALUE" ]]; }
