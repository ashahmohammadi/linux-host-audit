# Applying tuning advice. Each change is one setting, tested, reversible, and watched by the guard.

tune_advice() { awk -F '|' 'NF && $6 != ""' <<< "$TUNE_ROWS"; }

tune_list() {
    local n=0 group setting now used pct rec why how raw
    run_checks
    tune_collect
    title 'Tuning advice you can apply' 'One at a time, then watch a day of traffic before the next.'
    while IFS='|' read -r group setting now used pct rec why how raw; do
        [[ -n $setting ]] || continue
        ((n += 1))
        printf '  %2d  %-26.26s %-26.26s %s -> %s\n' "$n" "$group" "$setting" "$now" "$rec"
        printf '      %s%s%s\n' "$c_dim" "$why" "$c_off"
    done <<< "$(tune_advice)"
    ((n > 0)) || printf '  %s Nothing to change right now.\n' "$(badge OK)"
    ((n == 0)) || printf '\n  Apply one with: --tune-apply NUMBER. See the plan first with: --tune-apply NUMBER --dry-run\n'
}

# The included folder that this server really reads, so a saved setting is not silently ignored.
tune_mysql_dir() {
    local dir
    for dir in /etc/mysql/mariadb.conf.d /etc/mysql/mysql.conf.d /etc/mysql/conf.d /etc/my.cnf.d; do
        [[ -d $dir ]] || continue
        if grep -rqsE "^[[:space:]]*!includedir[[:space:]]+$dir" /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.cnf; then
            printf '%s' "$dir"
            return 0
        fi
    done
}

# Changes pm.max_children of one pool. A file can hold several pools, and the others stay.
tune_fpm_edit() {
    awk -v pool="[$2]" -v value="$3" '
        /^[ \t]*\[/ { line = $0; gsub(/[ \t]/, "", line); inside = (line == pool) }
        inside && /^[ \t]*pm\.max_children[ \t]*=/ { print "pm.max_children = " value; next }
        { print }' "$1"
}

fx_mysql_client() { sql_find; }
fx_mysql_get() { run_t 6 "${SQL[@]}" --connect-timeout=3 -NBe "SELECT @@GLOBAL.$1" 2>/dev/null; }

dx_tune_apply() {
    local n=${1:-0} line
    tune_collect
    [[ $n =~ ^[1-9][0-9]*$ ]] || n=0
    line=$(tune_advice | sed -n "${n}p")
    IFS='|' read -r TA_GROUP TA_SETTING TA_NOW _ _ TA_REC TA_WHY TA_HOW TA_RAW <<< "$line"
    if [[ -z $TA_SETTING ]]; then FX_CAUSE="There is no advice number $n."; return 0; fi
    FX_CAUSE="$TA_GROUP $TA_SETTING: $TA_WHY"
    FX_STEPS=("Now $TA_NOW, advised $TA_REC.")
    case $TA_GROUP in
        MariaDB*|MySQL*)
            fx_mysql_client
            case $TA_SETTING in
                max_connections|innodb_buffer_pool_size|tmp_table_size|table_open_cache|thread_cache_size|query_cache_type|innodb_redo_log_capacity|innodb_log_file_size)
                    if [[ $TA_HOW != live ]]; then
                        FX_STEPS+=("Under [mysqld] in your config, then a planned restart: $TA_SETTING = $TA_RAW")
                        tune_panel_steps mysql
                        return 0
                    fi
                    TA_KIND=mysql TA_DIR=$(tune_mysql_dir)
                    FX_MODE=auto FX_RISK=medium
                    FX_PLAN=("SET GLOBAL $TA_SETTING = $TA_RAW, with no restart.")
                    if [[ -n $TA_DIR ]]; then FX_PLAN+=("Save it in $TA_DIR/zz-linux-host-audit.cnf, so it survives a restart.")
                    else FX_PLAN+=('No included config folder was found, so this lasts until the next restart.')
                    fi ;;
                *) FX_STEPS+=("Under [mysqld] in your config, then a planned restart: $TA_SETTING = $TA_RAW")
                   tune_panel_steps mysql ;;
            esac ;;
        'Linux kernel')
            case $TA_SETTING in
                net.core.somaxconn|vm.swappiness)
                    TA_KIND=sysctl FX_MODE=auto FX_RISK=low
                    FX_PLAN=("sysctl $TA_SETTING=$TA_RAW, kept across reboots.") ;;
                transparent_hugepage)
                    TA_KIND=thp FX_MODE=auto FX_RISK=low
                    FX_PLAN=('Set transparent hugepages to madvise, until the next boot.')
                    FX_STEPS=('To keep it, add transparent_hugepage=madvise to the kernel command line.') ;;
                ip_local_port_range)
                    TA_KIND=sysctl TA_SETTING=net.ipv4.ip_local_port_range FX_MODE=auto FX_RISK=low
                    FX_PLAN=("sysctl $TA_SETTING=$TA_RAW, kept across reboots.") ;;
            esac ;;
        Redis*|Valkey*)
            if [[ $TA_SETTING == maxmemory ]]; then
                TA_KIND=redis FX_MODE=auto FX_RISK=medium TA_CLI=redis-cli
                has "$TA_CLI" || TA_CLI=valkey-cli
                FX_PLAN=("CONFIG SET maxmemory $TA_RAW. This is above what it uses now, so nothing is evicted.")
                FX_STEPS=('Also add it to the config file, or it resets at restart. Consider a maxmemory-policy.')
            fi ;;
        Apache*) tune_panel_steps apache "$TA_REC" ;;
        Nginx*)
            panel_find
            if [[ -n $PANEL ]]; then
                tune_panel_steps nginx
            elif [[ $TA_SETTING == worker_connections || $TA_SETTING == worker_processes ]]; then
                TA_KIND=nginx FX_MODE=auto FX_RISK=medium TA_FILE=/etc/nginx/nginx.conf
                [[ -r $TA_FILE ]] || TA_FILE=/usr/local/nginx/conf/nginx.conf
                FX_PLAN=("Set $TA_SETTING $TA_RAW in $TA_FILE." 'Test with nginx -t, then reload. Open connections stay.')
            fi ;;
        'PHP-FPM pools')
            TA_POOL=${TA_SETTING%% *}
            TA_FILE=$(grep -lsE "^\[$TA_POOL\]" /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf | head -n 1)
            panel_find
            if [[ -n $PANEL ]]; then
                tune_panel_steps fpm
            elif [[ -n $TA_FILE ]]; then
                TA_KIND=phpfpm FX_MODE=auto FX_RISK=medium
                # With several PHP versions, the file says which one owns this pool.
                if [[ $TA_FILE =~ ^/etc/php/([0-9.]+)/fpm/ ]]; then TA_UNIT=php${BASH_REMATCH[1]}-fpm.service
                else TA_UNIT=$(run_t 5 systemctl list-units --type=service --state=running --plain --no-legend 2>/dev/null | awk '$1 ~ /php.*fpm/ { print $1; exit }')
                fi
                FX_PLAN=("Set pm.max_children = $TA_RAW for pool $TA_POOL in $TA_FILE." "Test the config, then reload ${TA_UNIT:-php-fpm}.")
                FX_EXPECT_GONE=$TA_UNIT
            fi ;;
    esac
    case $TA_HOW:$FX_MODE in
        restart:*) FX_STEPS+=('This one needs a planned restart, so it is left to you.') ;;
    esac
}

ap_tune_apply() {
    local old file line
    case $TA_KIND in
        mysql)
            old=$(fx_mysql_get "$TA_SETTING")
            [[ -n $old ]] || return 1
            fx_quote "${SQL[@]}" -e "SET GLOBAL $TA_SETTING = $old"
            fx_undo "$REPLY"
            fx_run "${SQL[@]}" -e "SET GLOBAL $TA_SETTING = $TA_RAW" || return 1
            line=''
            # The smaller of these two is what counts, so they only ever move together.
            if [[ $TA_SETTING == tmp_table_size ]]; then
                old=$(fx_mysql_get max_heap_table_size)
                [[ -n $old ]] || return 1
                fx_quote "${SQL[@]}" -e "SET GLOBAL max_heap_table_size = $old"
                fx_undo "$REPLY"
                fx_run "${SQL[@]}" -e "SET GLOBAL max_heap_table_size = $TA_RAW" || return 1
                line=max_heap_table_size
            fi
            if [[ -n $TA_DIR ]]; then
                file=$TA_DIR/zz-linux-host-audit.cnf
                { printf '[mysqld]\n'
                  grep -v -e "^$TA_SETTING " -e "^${line:-none} " -e '^\[mysqld\]' "$file" 2>/dev/null
                  printf '%s = %s\n' "$TA_SETTING" "$TA_RAW"
                  [[ -z $line ]] || printf '%s = %s\n' "$line" "$TA_RAW"
                } | fx_write "$file"
            fi ;;
        sysctl) fx_sysctl "$TA_SETTING" "$TA_RAW" ;;
        thp)
            fx_undo 'echo always > /sys/kernel/mm/transparent_hugepage/enabled'
            echo madvise > /sys/kernel/mm/transparent_hugepage/enabled ;;
        redis)
            old=$(run_t 5 "$TA_CLI" -h 127.0.0.1 config get maxmemory | tail -n 1 | tr -d '\r')
            fx_quote "$TA_CLI" -h 127.0.0.1 config set maxmemory "$old"
            fx_undo "$REPLY"
            fx_run "$TA_CLI" -h 127.0.0.1 config set maxmemory "$TA_RAW" ;;
        nginx)
            fx_quote systemctl reload nginx
            fx_undo "$REPLY"
            sed -E "s/^([[:space:]]*${TA_SETTING}[[:space:]]+)[^;]+;/\1$TA_RAW;/" "$TA_FILE" | fx_write "$TA_FILE" || return 1
            nginx -t >/dev/null 2>&1 || return 1
            fx_run systemctl reload nginx ;;
        phpfpm)
            fx_quote systemctl reload "$TA_UNIT"
            fx_undo "$REPLY"
            tune_fpm_edit "$TA_FILE" "$TA_POOL" "$TA_RAW" | fx_write "$TA_FILE" || return 1
            # No app config changes without its own test.
            [[ -n $(fx_phpfpm_bin "$TA_UNIT") ]] || return 1
            fx_phpfpm_test "$TA_UNIT" >/dev/null 2>&1 || return 1
            fx_run systemctl reload "$TA_UNIT" ;;
        *) return 1 ;;
    esac
}

ck_tune_apply() {
    local value
    case $TA_KIND in
        mysql)
            value=$(fx_mysql_get "$TA_SETTING")
            case $TA_SETTING in
                # The server rounds the pool to its chunk size, and resizes in the background.
                innodb_buffer_pool_size|innodb_redo_log_capacity|innodb_log_file_size) ((value * 10 >= TA_RAW * 9 && value * 10 <= TA_RAW * 11)) ;;
                query_cache_type) [[ $value == OFF || $value == 0 ]] ;;
                *) [[ $value == "$TA_RAW" ]] ;;
            esac ;;
        sysctl) [[ $(sysctl -n "$TA_SETTING" | tr -s '\t ' ' ') == "$TA_RAW" ]] ;;
        thp) grep -q '\[madvise\]' /sys/kernel/mm/transparent_hugepage/enabled ;;
        redis) [[ $(run_t 5 "$TA_CLI" -h 127.0.0.1 config get maxmemory | tail -n 1 | tr -d '\r') == "$TA_RAW" ]] ;;
        nginx) grep -qE "^[[:space:]]*${TA_SETTING}[[:space:]]+$TA_RAW;" "$TA_FILE" && [[ $(run_t 3 systemctl is-active nginx) == active ]] ;;
        phpfpm) [[ $(tune_fpm_edit "$TA_FILE" "$TA_POOL" "$TA_RAW") == "$(cat "$TA_FILE")" && $(run_t 3 systemctl is-active "$TA_UNIT") == active ]] ;;
        *) return 1 ;;
    esac
}

# Menu pages, shown only in the fixer.
menu_page_fix() {
    local i state head='CHOOSE ONE, YOU SEE THE PLAN FIRST'
    menu_title='Fix problems'
    for ((i = 0; i < F_N && i < 30; i++)); do
        case ${F_SEV[i]} in CRIT) state=crit ;; WARN) state=warn ;; *) state=tool ;; esac
        menu_add "$state" "${F_ID[i]}" "${F_TARGET[i]}" "$head" "run:fix_from_menu ${F_ID[i]}:${F_TARGET[i]}"
        head=''
    done
    ((F_N > 0)) || menu_add ok 'Nothing to fix' '' 'ALL CLEAR' view_problems
}

menu_page_apply() {
    local n=0 group setting now used pct rec why how raw head='ONE AT A TIME, YOU SEE THE PLAN FIRST'
    menu_title='Apply tuning'
    tune_collect
    while IFS='|' read -r group setting now used pct rec why how raw; do
        [[ -n $setting ]] || continue
        ((n += 1))
        menu_add warn "$setting" "$now -> $rec" "$head" "run:fx_transaction tune-apply $n"
        head=''
    done <<< "$(tune_advice)"
    ((n > 0)) || menu_add ok 'Nothing to change right now' '' 'ALL CLEAR' view_tune
}

# The menu splits its action on spaces, and a target can hold spaces: an OS name, say.
fix_from_menu() {
    local want=$*
    fix_find "$want" || { fx_say 'This problem is no longer there.'; return 0; }
    fx_transaction "${F_ID[FOUND_INDEX]}" "${F_TARGET[FOUND_INDEX]}"
}
