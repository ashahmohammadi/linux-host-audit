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
        php)
            panel_find
            FX_STEPS=('Find the sites on it, then test each on a newer PHP.')
            case $PANEL in
                cpanel) FX_STEPS+=('WHM > Home > Software > MultiPHP Manager changes the PHP of each domain.' 'linux-host-audit.sh --panel lists how many sites use each version.') ;;
                plesk) FX_STEPS+=('plesk bin php_handler --list shows the handlers.' 'Domains > DOMAIN > PHP Settings changes the PHP of each domain.') ;;
                directadmin) FX_STEPS+=('da build set php1_release 8.3, then da build php, then da build rewrite_confs') ;;
            esac ;;
        mariadb|mysql|postgresql)
            panel_find
            FX_STEPS=('Back up every database first.' 'Test the application on a copy with the new version.')
            case $PANEL:$app in
                cpanel:mariadb|cpanel:mysql) FX_STEPS+=('WHM > Home > SQL Services > MySQL/MariaDB Upgrade') ;;
                directadmin:mariadb) FX_STEPS+=('da build set mysql_backup yes, da build set mariadb 11.4, da build mariadb') ;;
                directadmin:mysql) FX_STEPS+=('da build set mysql_backup yes, da build set mysql 8.4, da build mysql') ;;
            esac ;;
        *) FX_STEPS=('Test your application on a supported version.') ;;
    esac
}
dx_updates_many() { FX_MODE=never; FX_CAUSE='Many updates are waiting, none marked as security.'; FX_STEPS=('Run them in a maintenance window, after a backup.'); }
dx_backup_missing() {
    FX_CAUSE='No backup tool, and no scheduled job that mentions backups.'
    FX_MODE=never
    FX_STEPS=('Choose where backups live. It must not be this server.' 'Then test a restore. Untested backups often do not work.')
    panel_find
    case $PANEL in
        cpanel) FX_STEPS+=('WHM > Home > Backup > Backup Configuration') ;;
        plesk) FX_STEPS+=('Tools & Settings > Backup Manager') ;;
        directadmin) FX_STEPS+=('Admin Level > Admin Backup/Transfer') ;;
        *) FX_STEPS+=('Common choices: restic or borg.') ;;
    esac
}
dx_backup_old() { FX_CAUSE="Backups in $1 stopped."; FX_STEPS=('journalctl -u cron -u crond --since "3 days ago" | grep -i backup' "ls -lt $1 | head" 'crontab -l'); }
dx_monitoring_missing() { FX_CAUSE='Nothing alerts you when this server fails.'; FX_MODE=never; FX_STEPS=('Netdata or node_exporter are good starting points.' 'Or run from cron: linux-host-audit.sh --check, and alert on exit code 2.'); }
dx_mail_queue() {
    FX_CAUSE='Many emails are waiting.'
    if [[ -n $(sig_list RUNNING '^Exim') ]]; then
        local exim=exim
        has exim || exim=exim4
        FX_STEPS=("$exim -bp | exiqsumm | tail" "$exim -bp | head -20 shows sender addresses." 'exiwhat shows what Exim is doing now.')
    else
        FX_STEPS=('postqueue -p | tail shows the total.' 'postqueue -p | head -30 shows sender addresses.')
    fi
    FX_STEPS+=('If one account sends thousands, a site is hacked or a mailbox is stolen.')
}
dx_mysql_connections() { FX_CAUSE='Connections are close to max_connections.'; FX_STEPS=('SHOW FULL PROCESSLIST; look for slow queries first.' 'Raising the limit without that only uses more RAM.'); }
dx_postgres_connections() { FX_CAUSE='Connections are close to max_connections.'; FX_STEPS=('select state, count(*) from pg_stat_activity group by 1;' 'A connection pooler such as PgBouncer usually fixes this.'); }
dx_mysql_replication_stopped() { FX_MODE=never; FX_CAUSE='Replication stopped. Skipping an error can silently corrupt the replica.'; FX_STEPS=('SHOW REPLICA STATUS\G and read Last_Error. Before MySQL 8.0.22 and MariaDB 10.5: SHOW SLAVE STATUS\G' 'Fix the cause. Rebuild the replica if in doubt.'); }
dx_search_red() {
    FX_CAUSE='Some primary shards have no node.'
    FX_STEPS=('curl -s "localhost:9200/_cat/shards?v" | grep UNASSIGNED' 'curl -s "localhost:9200/_cluster/allocation/explain?pretty"'
        'With security on, the default since Elasticsearch 8: curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic "https://localhost:9200/_cluster/allocation/explain?pretty"')
}

# Hosting panels. Only guidance: a panel owns its files, and rewrites what others change.
dx_panel_eol() {
    FX_MODE=never
    panel_find
    FX_CAUSE="$1 is past its vendor's support."
    case $PANEL in
        cpanel) FX_STEPS=('WHM > Home > Server Configuration > Update Preferences: choose a supported tier.' 'WHM > Home > cPanel > Upgrade to Latest Version, or /usr/local/cpanel/scripts/upcp' 'You cannot go back to an older major version.') ;;
        plesk) FX_STEPS=('plesk listupgrade' 'plesk checkupgrade' 'plesk installer install-panel-updates') ;;
        *) FX_STEPS=('da update') ;;
    esac
}
dx_panel_down() {
    FX_MODE=never
    panel_find
    FX_CAUSE="$PANEL_NAME does not answer on its port."
    case $PANEL in
        cpanel) FX_STEPS=('/usr/local/cpanel/scripts/restartsrv_cpsrvd' 'tail -n 50 /usr/local/cpanel/logs/error_log') ;;
        plesk) FX_STEPS=('systemctl status psa sw-cp-server sw-engine' 'plesk log panel.log' 'plesk repair all -n checks everything and fixes nothing.' 'plesk repair all -y then repairs it. Run it off-peak, after a backup.') ;;
        *) FX_STEPS=('systemctl status directadmin' 'tail /var/log/directadmin/error.log' 'journalctl -u directadmin.service' 'Is the disk with /usr/local/directadmin/data/sessions full? df -h' 'For more detail: systemctl stop directadmin, then da server --debug=2000, and stop it with Ctrl+C. Then systemctl start directadmin') ;;
    esac
}
dx_panel_updates_off() {
    FX_MODE=never
    FX_CAUSE="UPDATES=$1 in /etc/cpupdate.conf."
    FX_STEPS=('WHM > Home > Server Configuration > Update Preferences: choose automatic updates.')
}
dx_panel_update_failed() {
    FX_MODE=never
    FX_CAUSE="Its log has no 'Completed all updates' line: $(tail -n 1 /var/cpanel/updatelogs/last 2>/dev/null | clean | cut -c1-120)"
    FX_STEPS=('Read the first error: grep -nE "ERROR|FATAL" /var/cpanel/updatelogs/last | head' 'Then run it again: /usr/local/cpanel/scripts/upcp')
}
dx_panel_queue_stuck() {
    FX_MODE=never
    FX_CAUSE="/usr/local/directadmin/data/task.queue is $1 minutes old. It should be gone within minutes."
    FX_STEPS=('tail -n 20 /var/log/directadmin/errortaskq.log' 'killall -USR1 dataskq, then read that log again to see what it is doing.' 'Is the nightly tally running? tail /var/log/directadmin/system.log' 'Run it once by hand, with debug output: /usr/local/directadmin/dataskq d80')
}

# How a service restarts on this panel. On cPanel the vendor names its own script first.
panel_restart_step() {
    local unit=${1%.service} name
    panel_find
    case $PANEL:$unit in
        cpanel:httpd) name=httpd ;; cpanel:mysqld|cpanel:mariadb) name=mysql ;; cpanel:exim) name=exim ;;
        cpanel:dovecot) name=dovecot ;; cpanel:named) name=named ;; cpanel:nginx) name=nginx ;;
        cpanel:cpanel|cpanel:cpsrvd) name=cpsrvd ;; cpanel:queueprocd) name=queueprocd ;; *) return 0 ;;
    esac
    FX_STEPS+=("/usr/local/cpanel/scripts/restartsrv_$name")
}

# Each panel has its own place for a setting, and rewrites the files it generates.
tune_panel_steps() {
    local kind=$1 value=${2:-THE_VALUE}
    panel_find
    case $PANEL:$kind in
        cpanel:apache)
            FX_STEPS+=("WHM > Home > Service Configuration > Apache Configuration > Global Configuration: Max Request Workers $value, and Server Limit if needed."
                'Then click Rebuild Configuration and Restart Apache. Do not edit /etc/cpanel/ea4/ea4.conf by hand.') ;;
        plesk:apache)
            FX_STEPS+=('Find the MPM: httpd -V | grep MPM, on Debian and Ubuntu: apache2ctl -V | grep MPM'
                "RHEL family: set MaxRequestWorkers $value in /etc/httpd/conf.modules.d/01-cgi.conf. Debian, Ubuntu: in /etc/apache2/mods-enabled/mpm_event.conf or mpm_prefork.conf."
                'Then restart Apache. Plesk sets the formula: (RAM minus other programs) / average Apache process size.') ;;
        directadmin:apache)
            FX_STEPS+=('cd /usr/local/directadmin/custombuild; mkdir -p custom/ap2/conf/extra/; cp -fp configure/ap2/conf/extra/httpd-mpm.conf custom/ap2/conf/extra/httpd-mpm.conf'
                "Set MaxRequestWorkers $value in custom/ap2/conf/extra/httpd-mpm.conf, then: da build rewrite_confs") ;;
        :apache)
            FX_STEPS+=("Set MaxRequestWorkers $value in the file of your MPM, and ServerLimit with it." 'Test with apachectl -t. A new ServerLimit needs a full restart, a reload ignores it.') ;;
        cpanel:fpm)
            FX_STEPS+=('One domain: WHM > Home > Software > MultiPHP Manager > User Domain Settings > PHP-FPM Settings.'
                'All domains: set pm_max_children in /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml, then /usr/local/cpanel/scripts/php_fpm_config --rebuild'
                'cPanel rewrites /opt/cpanel/ea-php*/root/etc/php-fpm.d/, so do not edit those files.') ;;
        plesk:fpm)
            FX_STEPS+=('Domains > DOMAIN > PHP Settings: pm.max_children. Service plans have the same setting.') ;;
        directadmin:fpm)
            FX_STEPS+=('One domain: Admin Level > Custom Httpd Config > DOMAIN: php-fpm, then |?MAX_CHILDREN=200| in the CUSTOM1 area.'
                'All domains: da config-set php_fpm_max_children_default 100, then da build rewrite_confs, then systemctl restart php-fpm83 with your PHP version.') ;;
        cpanel:nginx)
            FX_STEPS+=('Back up /etc/nginx/ea-nginx/settings.json, then change the value there.' 'nginx -t, then /usr/local/cpanel/scripts/restartsrv_nginx') ;;
        plesk:nginx)
            FX_STEPS+=('Set it in /etc/nginx/nginx.conf. Plesk writes its own files under /etc/nginx/conf.d and /etc/nginx/plesk.conf.d.' 'nginx -t, then systemctl reload nginx') ;;
        directadmin:nginx)
            FX_STEPS+=('CustomBuild owns nginx.conf. Copy the file from custombuild/configure/ to the same place under custombuild/custom/, edit that one, then: da build rewrite_confs') ;;
        cpanel:mysql) FX_STEPS+=('/etc/my.cnf holds the settings. After a change: /usr/local/cpanel/scripts/restartsrv_mysql') ;;
    esac
}

guide_fallback() {
    FX_CAUSE='No detailed diagnosis exists for this yet.'
    FX_STEPS=("See the Next command in the report for $1.")
}
