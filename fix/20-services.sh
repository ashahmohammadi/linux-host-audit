# Failed services: find the exact reason first. Only a clean retry is ever automatic.

# Read-only config test for a service, if it has one. Sets FX_CONFIG_ERROR.
fx_config_test() {
    local unit=${1%.service} out=''
    FX_CONFIG_ERROR=
    case $unit in
        nginx*) has nginx && out=$(run_t 10 nginx -t 2>&1) || FX_CONFIG_ERROR=$out ;;
        apache2*) has apache2ctl && out=$(run_t 10 apache2ctl configtest 2>&1) || FX_CONFIG_ERROR=$out ;;
        httpd*) has apachectl && out=$(run_t 10 apachectl configtest 2>&1) || FX_CONFIG_ERROR=$out ;;
        ssh|sshd) has sshd && out=$(run_t 10 sshd -t 2>&1) || FX_CONFIG_ERROR=$out ;;
        haproxy*) has haproxy && out=$(run_t 10 haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1) || FX_CONFIG_ERROR=$out ;;
        php*-fpm*) has php-fpm && out=$(run_t 10 php-fpm -t 2>&1) || FX_CONFIG_ERROR=$out ;;
        postfix*) has postfix && out=$(run_t 10 postfix check 2>&1) || FX_CONFIG_ERROR=$out ;;
        named*|bind9*) has named-checkconf && out=$(run_t 10 named-checkconf 2>&1) || FX_CONFIG_ERROR=$out ;;
    esac
    FX_CONFIG_ERROR=$(printf '%s' "$FX_CONFIG_ERROR" | clean | grep -v 'syntax is ok\|test is successful' | tail -n 2 | tr '\n' ' ' | cut -c1-200)
}

fx_unit_log() { run_t 8 journalctl -u "$1" -n 60 --no-pager -q -o cat 2>/dev/null | clean; }

dx_service_failed() {
    local unit=${1:-} result status log port owner path pkg
    [[ -n $unit ]] || { FX_CAUSE='No service was named.'; return 0; }
    result=$(run_t 3 systemctl show -p Result --value -- "$unit" 2>/dev/null)
    status=$(run_t 3 systemctl show -p ExecMainStatus --value -- "$unit" 2>/dev/null)
    log=$(fx_unit_log "$unit")
    FX_STEPS=("systemctl status $unit" "journalctl -u $unit -n 100 --no-pager")

    fx_config_test "$unit"
    if [[ -n $FX_CONFIG_ERROR ]]; then
        FX_CAUSE="Its configuration is broken: $FX_CONFIG_ERROR"
        FX_STEPS=('Correct that line. This tool will not edit an app config by guessing.' "${FX_STEPS[@]}")
        return 0
    fi
    case $(tr 'A-Z' 'a-z' <<< "$log") in
        *'address already in use'*)
            port=$(grep -io 'address already in use' -B0 <<< "$log" >/dev/null; grep -oE ':[0-9]{2,5}' <<< "$log" | tail -n 1 | tr -d :)
            owner=$(awk -v p="$port" '$2 == p { print $5; exit }' <<< "$NET_ROWS")
            FX_CAUSE="Port ${port:-unknown} is already taken${owner:+ by $owner}."
            FX_STEPS=('Stop the other program, or give one of them another port.' "ss -lntup | grep :$port")
            return 0 ;;
        *'no space left'*|*'disk quota exceeded'*)
            FX_CAUSE='It could not write: the disk or a quota is full.'
            FX_STEPS=('Fix the disk first, then run this fix again.')
            return 0 ;;
        *'read-only file system'*)
            FX_CAUSE='The filesystem it needs is read-only.'
            FX_STEPS=('This usually means disk errors: dmesg | tail -30')
            return 0 ;;
        *'permission denied'*)
            path=$(grep -i 'permission denied' <<< "$log" | grep -oE '/[^ :"]+' | tail -n 1)
            FX_CAUSE="Permission denied${path:+ on $path}."
            FX_STEPS=("ls -ld ${path:-THE_PATH}" 'Compare owner and mode with the User= of the service.' "${FX_STEPS[@]}")
            return 0 ;;
    esac
    case $result in
        oom-kill)
            FX_CAUSE='The kernel killed it because memory ran out. Restarting alone would only repeat this.'
            FX_STEPS=('See the oom-kills and memory-low findings.')
            return 0 ;;
        exit-code)
            if [[ $status == 203 ]]; then
                path=$(run_t 3 systemctl show -p ExecStart --value -- "$unit" 2>/dev/null | grep -oE 'path=[^ ;]+' | head -n 1)
                path=${path#path=}
                FX_CAUSE="Its program could not run: ${path:-unknown path} is missing or not executable."
                if has rpm; then pkg=$(rpm -qf "$path" 2>/dev/null); elif has dpkg; then pkg=$(dpkg -S "$path" 2>/dev/null | cut -d: -f1); fi
                FX_STEPS=("ls -l $path" "Reinstall its package${pkg:+: $pkg}.")
                return 0
            fi ;;
    esac
    FX_CAUSE="It stopped with result ${result:-unknown}, exit status ${status:-unknown}. Last log: $(tail -n 1 <<< "$log" | cut -c1-120)"
    FX_MODE=auto FX_RISK=medium
    FX_PLAN=("Clear its failed state and start it once: systemctl start $unit")
    if [[ $(run_t 3 systemctl show -p Type --value -- "$unit" 2>/dev/null) == oneshot ]]; then
        FX_CAUSE+=' It is a one-shot task.'
    fi
    FX_EXPECT_GONE=$unit
}
ap_service_failed() {
    fx_quote systemctl stop "$1"
    fx_undo "$REPLY"
    fx_run systemctl reset-failed "$1"
    fx_run systemctl start "$1"
}
ck_service_failed() {
    local state i
    for ((i = 0; i < 4; i++)); do
        state=$(run_t 3 systemctl is-active "$1" 2>/dev/null)
        [[ $state == failed ]] && return 1
        sleep 1
    done
    [[ $state == active ]]
}

# Database, engine and cache outages are service problems, with a known unit name.
fx_first_unit() {
    local unit
    for unit in "$@"; do
        if [[ $units == *$'\n'"$unit.service "* || $active_units == *$'\n'"$unit.service "* ]]; then
            printf '%s.service' "$unit"
            return 0
        fi
    done
}
fx_delegate() {
    FX_UNIT=$1
    if [[ -z $FX_UNIT ]]; then FX_CAUSE='Its service unit could not be found.'; return 0; fi
    dx_service_failed "$FX_UNIT"
}
dx_mysql_down() { fx_delegate "$(fx_first_unit mariadb mysql mysqld)"; }
ap_mysql_down() { ap_service_failed "$FX_UNIT"; }
ck_mysql_down() { ck_service_failed "$FX_UNIT"; }
dx_postgres_down() { fx_delegate "$(fx_first_unit postgresql)"; }
ap_postgres_down() { ap_service_failed "$FX_UNIT"; }
ck_postgres_down() { ck_service_failed "$FX_UNIT"; }
dx_redis_down() { fx_delegate "$(fx_first_unit redis redis-server valkey valkey-server)"; }
ap_redis_down() { ap_service_failed "$FX_UNIT"; }
ck_redis_down() { ck_service_failed "$FX_UNIT"; }
dx_engine_down() { fx_delegate "$(fx_first_unit "$1" "$1.socket")"; }
ap_engine_down() { ap_service_failed "$FX_UNIT"; }
ck_engine_down() { ck_service_failed "$FX_UNIT"; }

dx_redis_save_failing() {
    local log over
    over=$(sysctl -n vm.overcommit_memory 2>/dev/null)
    log=$(fx_unit_log "$(fx_first_unit redis redis-server valkey valkey-server)" | grep -i 'fork\|save\|rdb\|permission' | tail -n 2 | cut -c1-140)
    FX_CAUSE="Saving failed. ${log:-No clear log line.}"
    FX_STEPS=('Check free disk and the owner of the data folder.' 'redis-cli config get dir' 'redis-cli info persistence')
    if [[ $over == 0 && $log == *[Ff]ork* ]]; then
        FX_CAUSE='Redis cannot fork to save, because the kernel refuses to overcommit memory.'
        FX_MODE=auto FX_RISK=low
        FX_PLAN=('Set vm.overcommit_memory=1, as Redis itself recommends.')
    fi
}
ap_redis_save_failing() { fx_sysctl vm.overcommit_memory 1; }
ck_redis_save_failing() { [[ $(sysctl -n vm.overcommit_memory) == 1 ]]; }

# Certificates: renew with whichever tool issued them.
fx_tls_dx() {
    local name=$1
    FX_CERT=/etc/letsencrypt/live/$name/fullchain.pem
    if [[ -r $FX_CERT ]] && has certbot; then
        FX_CAUSE="Let's Encrypt certificate $name has not renewed."
        FX_MODE=auto FX_RISK=low
        FX_PLAN=("Renew it: certbot renew --cert-name $name" 'Reload web servers that run, to load the new file.')
        FX_STEPS=('If this fails, port 80 or the DNS record usually does not reach this server.' "certbot renew --dry-run --cert-name $name")
    elif [[ -x /usr/local/cpanel/bin/autossl_check ]]; then
        FX_CAUSE="cPanel AutoSSL has not renewed $name."
        FX_STEPS=('/usr/local/cpanel/bin/autossl_check --all' 'WHM > SSL/TLS > Manage AutoSSL > Logs shows why a domain failed.')
    elif [[ -x /root/.acme.sh/acme.sh ]]; then
        FX_CAUSE="$name looks issued by acme.sh, which has not renewed it."
        FX_STEPS=('/root/.acme.sh/acme.sh --cron' '/root/.acme.sh/acme.sh --list')
    else
        FX_CAUSE="No renewal tool was found for $name. It may be bought or manually installed."
        FX_STEPS=('Renew it where you got it, then install the new file.')
    fi
}
fx_tls_ap() {
    local name=$1 unit
    fx_backup /etc/letsencrypt/renewal/"$name".conf
    fx_run certbot renew --cert-name "$name" || return 1
    for unit in nginx apache2 httpd; do
        [[ $(run_t 3 systemctl is-active "$unit" 2>/dev/null) != active ]] || fx_run systemctl reload "$unit"
    done
    return 0
}
fx_tls_ck() { openssl x509 -checkend $((21 * 86400)) -noout -in "$FX_CERT" >/dev/null 2>&1; }
dx_tls_expired() { fx_tls_dx "$1"; }
ap_tls_expired() { fx_tls_ap "$1"; }
ck_tls_expired() { fx_tls_ck; }
dx_tls_expiring_soon() { fx_tls_dx "$1"; }
ap_tls_expiring_soon() { fx_tls_ap "$1"; }
ck_tls_expiring_soon() { fx_tls_ck; }
dx_tls_expiring() { fx_tls_dx "$1"; }
ap_tls_expiring() { fx_tls_ap "$1"; }
ck_tls_expiring() { fx_tls_ck; }
