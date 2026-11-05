# Recording history. One light sample at a time, reading the kernel directly.
TREND_BIN=/usr/local/sbin/linux-host-fix
TREND_CRON=/etc/cron.d/linux-host-audit

trend_record() {
    local cpu load ram swap disk conns php db=0 oom file
    mkdir -p "$TREND_DIR" || return 1
    chmod 700 "$TREND_DIR"
    metrics_snapshot
    sleep 1
    metrics_snapshot
    cpu=$cpu_pct ram=$ram_pct
    read -r load _ < /proc/loadavg
    swap=$(awk '/^SwapTotal:/ { t = $2 } /^SwapFree:/ { f = $2 } END { if (t > 0) printf "%d", (t - f) * 100 / t; else print 0 }' /proc/meminfo)
    disk=$(disk_rows | awk '$2 + 0 > m { m = $2 + 0 } END { print m + 0 }')
    conns=0
    conns=$(tcp_count 01 0 65535)
    php=$(ps -eo args= 2>/dev/null | grep -c '^php-fpm[0-9.]*: pool')
    if ps -eo comm= 2>/dev/null | grep -qE '^(mariadbd|mysqld)$'; then
        sql_find
        if has "${SQL[0]}"; then
            db=$(run_t 4 "${SQL[@]}" --connect-timeout=2 -NBe "SHOW GLOBAL STATUS LIKE 'Threads_connected'" 2>/dev/null | awk '{ print $2 + 0 }')
        fi
    fi
    oom=$(awk '$1 == "oom_kill" { print $2 }' /proc/vmstat 2>/dev/null)
    file=$TREND_DIR/$(date +%Y-%m).csv
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$(date +%s)" "${cpu:-0}" "${load:-0}" "${ram:-0}" "${swap:-0}" \
        "${disk:-0}" "${conns:-0}" "${php:-0}" "${db:-0}" "${oom:-0}" >> "$file"
    find "$TREND_DIR" -type f -name '*.csv' -mtime +100 -delete 2>/dev/null
    return 0
}

dx_trends_on() {
    FX_CAUSE='Recording is off, so only the present moment can be seen.'
    if [[ ! -d /etc/cron.d ]]; then FX_STEPS=('This system has no /etc/cron.d folder.'); return 0; fi
    if [[ ! -f ${FX_SELF:-} ]]; then
        FX_STEPS=('Save this file first, then run it: it copies itself for cron to use.')
        return 0
    fi
    FX_MODE=auto FX_RISK=low
    FX_PLAN=("Copy this tool to $TREND_BIN." "Add $TREND_CRON: one sample every 5 minutes, at the lowest priority."
        "Data goes to $TREND_DIR, about 40 MiB a year, and older than 100 days is removed.")
}
ap_trends_on() {
    fx_backup "$TREND_BIN" || return 1
    fx_run cp "$FX_SELF" "$TREND_BIN" || return 1
    fx_run chmod 755 "$TREND_BIN" || return 1
    # Alpine and other small systems have no ionice, and cron would fail with no trace.
    local quiet=''
    if has ionice; then quiet='ionice -c3 '; fi
    printf 'SHELL=/bin/bash\n*/5 * * * * root nice -n 19 %s%s --record >/dev/null 2>&1\n' "$quiet" "$TREND_BIN" | fx_write "$TREND_CRON"
    chmod 644 "$TREND_CRON"
    fx_run "$TREND_BIN" --record
}
ck_trends_on() { [[ -f $TREND_CRON ]] && ls "$TREND_DIR"/*.csv >/dev/null 2>&1; }

dx_trends_off() {
    FX_CAUSE='Recording is on.'
    if [[ ! -f $TREND_CRON ]]; then FX_CAUSE='Recording is already off.'; return 0; fi
    FX_MODE=auto FX_RISK=low
    FX_PLAN=("Remove $TREND_CRON and $TREND_BIN." "Keep the recorded data in $TREND_DIR.")
}
ap_trends_off() {
    fx_backup "$TREND_CRON" || return 1
    fx_backup "$TREND_BIN" || return 1
    fx_run rm -f "$TREND_CRON" "$TREND_BIN"
}
ck_trends_off() { [[ ! -e $TREND_CRON ]]; }
