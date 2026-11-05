# Problems that software must not change alone. Each still gets its exact cause and exact steps.

dx_not_root() { FX_CAUSE='Most checks and all fixes need root.'; FX_STEPS=('sudo bash linux-host-fix.sh'); }

dx_load_high() {
    local running blocked
    running=$(awk '/^procs_running/ { print $2 }' /proc/stat)
    blocked=$(awk '/^procs_blocked/ { print $2 }' /proc/stat)
    if ((blocked > running)); then FX_CAUSE="$blocked processes are stuck waiting for disk, $running running. The disk is the limit."
    else FX_CAUSE="$running processes want a CPU. Top: $(ps -eo pcpu=,comm= --sort=-pcpu 2>/dev/null | head -n 3 | clean | awk '{ printf "%s (%s%%) ", $2, $1 }')"
    fi
    FX_STEPS=('top -o %CPU' 'iostat -x 1 3')
}
dx_cpu_steal() { FX_CAUSE='Your VM waits for the physical CPU. The host is oversold.'; FX_STEPS=('Nothing inside this server fixes it.' 'Ask your provider to move it, or take a bigger plan.'); }
dx_io_wait() {
    FX_CAUSE='The disk cannot keep up.'
    FX_STEPS=('iostat -x 1 3 shows which disk.' 'iotop -oa shows which program.' 'Check slow SQL queries and running backups.')
}
dx_zombies() {
    local parent
    parent=$(ps -eo stat=,ppid= 2>/dev/null | awk '$1 ~ /^Z/ { n[$2]++ } END { for (p in n) print n[p], p }' | sort -rn | head -n 1 | awk '{ print $2 }')
    FX_CAUSE="Their parent is not collecting them${parent:+: $(ps -o comm= -p "$parent" 2>/dev/null)}. Zombies use almost nothing."
    FX_STEPS=('Restarting that parent clears them, when convenient.')
}
dx_fs_readonly() {
    FX_MODE=never
    FX_CAUSE="$1 went read-only, usually because of disk errors. Forcing it writable can destroy data."
    FX_STEPS=('Take a backup first, if you still can.' 'dmesg | grep -iE "error|ext4|xfs"' 'Check the filesystem from rescue mode: fsck on ext4, xfs_repair on XFS.')
}
dx_raid_degraded() {
    FX_MODE=never
    FX_CAUSE="$(grep -B1 '\[[U]*_[U_]*\]' /proc/mdstat 2>/dev/null | head -n 2 | tr '\n' ' ' | cut -c1-140)"
    FX_STEPS=('A disk failed. Replace the hardware.' 'mdadm --detail /dev/mdX shows which one.' 'Check your backup before the rebuild.')
}
dx_zfs_unhealthy() { FX_MODE=never; FX_CAUSE=$(run_t 5 zpool status -x 2>/dev/null | head -n 4 | tr '\n' ' ' | cut -c1-160); FX_STEPS=('zpool status -v' 'Replace a faulted disk with zpool replace.'); }
dx_smart_failing() { FX_MODE=never; FX_CAUSE="$1 itself predicts failure. Software cannot repair it."; FX_STEPS=('Back up now.' "smartctl -a $1" 'Replace the drive.'); }
dx_disk_errors() {
    FX_MODE=never
    FX_CAUSE=$(kernel_log | clean | grep -iE 'i/o error|ext4-fs error|blk_update_request' | grep -iv 'command line' | tail -n 1 | cut -c1-140)
    FX_STEPS=('Back up now.' 'smartctl -a /dev/sdX' 'On a VM, ask your provider to check the storage.')
}
dx_kernel_faults() {
    FX_MODE=never
    FX_CAUSE=$(kernel_log | clean | grep -iE 'machine check events|hardware error|soft lockup|blocked for more than|segfault' | tail -n 1 | cut -c1-140)
    FX_STEPS=('A segfault points to that program. Hardware errors point to RAM or CPU.' 'journalctl -k -p warning --since "7 days ago"')
}
dx_kernel_pending() { FX_MODE=never; FX_CAUSE="$1 is installed, but activates only at reboot."; FX_STEPS=('Reboot at a planned moment. This tool never reboots a server.'); }
dx_reboot_required() { FX_MODE=never; FX_CAUSE="Packages that need it: $(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null | cut -c1-120)"; FX_STEPS=('Reboot at a planned moment. This tool never reboots a server.'); }

dx_no_default_route() { FX_MODE=never; FX_CAUSE='No gateway is configured. A wrong change here cuts off remote access.'; FX_STEPS=('ip route' 'Compare with your provider network settings, and fix it from the console.'); }
dx_no_dns() { FX_CAUSE='/etc/resolv.conf has no nameserver line.'; FX_STEPS=('On systemd-resolved: resolvectl status' 'Otherwise add your provider DNS server to the network config.'); }
dx_port_unknown() {
    local port=${1%%/*} pid exe=''
    pid=$(awk -v p="$port" '$2 == p { print $6; exit }' <<< "$NET_ROWS")
    [[ $pid != - ]] && exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    FX_CAUSE="Program: ${exe:-unknown}, PID ${pid:-unknown}."
    FX_MODE=never
    FX_STEPS=('Only you know if this should be public.' "ss -lntup | grep :$port" 'If not, block it in the firewall.')
}
dx_db_listens_all() {
    port_name "$1"
    FX_CAUSE="$REPLY listens on all interfaces. The firewall reports: $NET_FW."
    FX_STEPS=('From another network: nc -vz THIS_SERVER '"$1" 'If it connects, block it in the firewall.')
}
dx_extra_uid0() {
    FX_MODE=never
    FX_CAUSE="Accounts with root power: $1."
    FX_STEPS=('Who created it, and why? A removal could cut off a tool or a person.' 'last -n 20' 'If nobody knows it, treat this server as compromised.')
}
dx_exe_in_tmp() {
    FX_MODE=never
    FX_CAUSE="Program: $(readlink "/proc/$1/exe" 2>/dev/null | clean), user $(ps -o user= -p "$1" 2>/dev/null)."
    FX_STEPS=('Keep the evidence. Killing it first destroys what you need to see.' "ls -l /proc/$1/exe /proc/$1/cwd" "cat /proc/$1/cmdline | tr '\\0' ' '" 'Build updaters also run from /tmp, so check before you worry.')
}
dx_os_eol() {
    FX_MODE=never
    FX_CAUSE="Support for $1 ended in $H_EOL. An upgrade replaces most of the system."
    case $H_OS_ID in
        ubuntu) FX_STEPS=('Back up, test on a copy, then: do-release-upgrade' 'Or enable Ubuntu Pro for extended updates.') ;;
        debian) FX_STEPS=('Back up, test on a copy, then follow the official Debian upgrade notes.') ;;
        centos) FX_STEPS=('Migrate with ELevate to AlmaLinux or Rocky Linux, on a copy first.') ;;
        *) FX_STEPS=('Follow the upgrade guide of your OS, on a copy first.') ;;
    esac
}
dx_app_eol() {
    local app=${1%%:*}
    FX_MODE=never
    FX_CAUSE="$1 is past its official support. Upgrading can break the code running on it."
    case $app in
        php) FX_STEPS=('Find the sites on it, then test each on a newer PHP.' 'On cPanel: WHM > MultiPHP Manager.') ;;
        mariadb|mysql|postgresql) FX_STEPS=('Back up every database first.' 'Test the application on a copy with the new version.') ;;
        *) FX_STEPS=('Test your application on a supported version.') ;;
    esac
}
dx_updates_many() { FX_MODE=never; FX_CAUSE='Many updates are waiting, none marked as security.'; FX_STEPS=('Run them in a maintenance window, after a backup.'); }
dx_backup_missing() {
    FX_CAUSE='No backup tool, and no scheduled job that mentions backups.'
    FX_MODE=never
    FX_STEPS=('Choose where backups live. It must not be this server.' 'Then test a restore. Untested backups often do not work.' 'Common choices: restic, borg, or your panel backup.')
}
dx_backup_old() { FX_CAUSE="Backups in $1 stopped."; FX_STEPS=('grep -i backup /var/log/syslog /var/log/cron | tail' "ls -lt $1 | head" 'crontab -l'); }
dx_monitoring_missing() { FX_CAUSE='Nothing alerts you when this server fails.'; FX_MODE=never; FX_STEPS=('Netdata or node_exporter are good starting points.' 'Or run from cron: linux-host-audit.sh --check, and alert on exit code 2.'); }
dx_mail_queue() {
    FX_CAUSE='Many emails are waiting.'
    FX_STEPS=('exim -bp | exiqsumm | tail' 'exim -bp | head -20 shows sender addresses.' 'If one account sends thousands, a site is hacked or a mailbox is stolen.')
}
dx_mysql_connections() { FX_CAUSE='Connections are close to max_connections.'; FX_STEPS=('SHOW FULL PROCESSLIST; look for slow queries first.' 'Raising the limit without that only uses more RAM.'); }
dx_postgres_connections() { FX_CAUSE='Connections are close to max_connections.'; FX_STEPS=('select state, count(*) from pg_stat_activity group by 1;' 'A connection pooler such as PgBouncer usually fixes this.'); }
dx_mysql_replication_stopped() { FX_MODE=never; FX_CAUSE='Replication stopped. Skipping an error can silently corrupt the replica.'; FX_STEPS=('SHOW SLAVE STATUS\G and read Last_Error.' 'Fix the cause. Rebuild the replica if in doubt.'); }
dx_search_red() { FX_CAUSE='Some primary shards have no node.'; FX_STEPS=('curl -s localhost:9200/_cat/shards?v | grep UNASSIGNED' 'curl -s localhost:9200/_cluster/allocation/explain?pretty'); }

guide_fallback() {
    FX_CAUSE='No detailed diagnosis exists for this yet.'
    FX_STEPS=("See the Next command in the report for $1.")
}
