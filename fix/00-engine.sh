# Fix engine. Everything that changes a server goes through the fx_ functions in this file.
#
# Rules every fix must keep:
#   dx_* functions only read. They run in dry-run mode and on production.
#   ap_* functions change things only through fx_run, fx_write, fx_backup and fx_undo.
#   Every change registers its undo before it happens.
#   No fix deletes user data, reboots, or edits an application's config without a test command.

FX_HOME=${LHA_FIX_HOME:-/var/lib/linux-host-audit}
FX_DRY=no FX_ASSUME=none FX_STAMP=0 FX_DEADMAN_PID=
FX_SETTLE=${LHA_FIX_SETTLE:-4} FX_GUARD_RETRY=${LHA_FIX_GUARD_RETRY:-15} FX_DEADMAN_SECONDS=${LHA_FIX_DEADMAN:-120}
FX_LOCK=${LHA_FIX_LOCK:-/dev/shm/linux-host-audit.lock} FX_TIMEOUT=300

fx_say() { printf '%s\n' "$*"; }
fx_log() { [[ -z ${FX_DIR:-} ]] || printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$FX_DIR/journal.log"; }

# Opens one transaction. It lives on disk, so an undo still works after a crash or lost session.
fx_begin() {
    ((FX_STAMP += 1))
    FX_RUN=$(date +%Y%m%d-%H%M%S)-$$-$FX_STAMP
    FX_DIR=$FX_HOME/runs/$FX_RUN
    # A full disk is one of the things we fix, so fall back to memory for the transaction.
    if ! mkdir -p "$FX_DIR/files" 2>/dev/null || ! : > "$FX_DIR/undo.list" 2>/dev/null; then
        FX_DIR=/dev/shm/linux-host-audit/$FX_RUN
        mkdir -p "$FX_DIR/files" || return 1
        : > "$FX_DIR/undo.list" || return 1
    fi
    chmod 700 "$FX_DIR"
    printf '%s\n' "$1" > "$FX_DIR/what"
}

# Queues one shell line for rollback. Lines run newest first.
fx_undo() { printf '%s\n' "$1" >> "$FX_DIR/undo.list"; }

fx_quote() {
    local word out=''
    for word in "$@"; do printf -v word '%q' "$word"; out+="$word "; done
    REPLY=$out
}

fx_backup() {
    local path=$1 copy
    copy=$FX_DIR/files$path
    if [[ -e $path || -L $path ]]; then
        mkdir -p "${copy%/*}" || return 1
        cp -a "$path" "$copy" || return 1
        fx_quote cp -a "$copy" "$path"
    else
        fx_quote rm -f "$path"
    fi
    fx_undo "$REPLY"
    fx_log "backup $path"
}

# Replaces a file from stdin in one atomic step, keeping owner and mode.
fx_write() {
    local path=$1 temp
    # Writing through a link keeps it. Replacing it would leave the real file behind, unchanged.
    if [[ -L $path ]]; then path=$(readlink -f "$path") || return 1; fi
    temp=$path.lha-new
    fx_backup "$path" || return 1
    cat > "$temp" || { rm -f "$temp"; return 1; }
    # A failed command at the start of the pipe leaves nothing here, and that must not win.
    if [[ -s $path && ! -s $temp ]]; then
        rm -f "$temp"
        fx_log "refused to empty $path"
        return 1
    fi
    if [[ -e $path ]]; then
        chmod --reference="$path" "$temp" 2>/dev/null
        chown --reference="$path" "$temp" 2>/dev/null
    fi
    mv -f "$temp" "$path" || { rm -f "$temp"; return 1; }
    fx_log "wrote $path"
}

fx_run() {
    local status
    fx_quote "$@"
    fx_log "run $REPLY"
    if has timeout; then timeout "$FX_TIMEOUT" "$@" </dev/null >> "$FX_DIR/journal.log" 2>&1
    else "$@" </dev/null >> "$FX_DIR/journal.log" 2>&1
    fi
    status=$?
    fx_log "exit $status"
    return "$status"
}

fx_rollback() {
    local line
    [[ -s ${FX_DIR:-/nonexistent}/undo.list ]] || return 0
    fx_log 'rollback started'
    while IFS= read -r line; do
        fx_log "undo $line"
        bash -c "$line" >> "$FX_DIR/journal.log" 2>&1 || fx_log "undo step failed: $line"
    done <<< "$(awk '{ line[NR] = $0 } END { for (i = NR; i > 0; i--) print line[i] }' "$FX_DIR/undo.list")"
    : > "$FX_DIR/undo.list"
    fx_log 'rollback finished'
}

# The guard: what is alive now. Anything alive before a fix must be alive after it.
fx_alive() {
    if has systemctl; then
        run_t 8 systemctl list-units --type=service --state=running --plain --no-legend --no-pager 2>/dev/null |
            awk '$1 !~ /^(session-|run-|user@|systemd-|getty|serial-getty)/ { print "service", $1 }'
    fi
    net_listeners | awk '$2 + 0 < 32768 { print "port", $1 "/" $2, $4 }'
    if has docker; then
        run_t 8 docker ps --format 'container {{.Names}}' 2>/dev/null
    fi
}

fx_guard_take() { fx_alive | sort -u > "$FX_DIR/alive.before"; }

# Sets FX_LOST. Restarts take a moment, so a fresh loss is rechecked before it counts.
fx_guard_check() {
    local waited=0
    while :; do
        fx_alive | sort -u > "$FX_DIR/alive.after"
        FX_LOST=$(comm -23 "$FX_DIR/alive.before" "$FX_DIR/alive.after")
        if [[ -n ${FX_EXPECT_GONE:-} ]]; then FX_LOST=$(grep -Ev "$FX_EXPECT_GONE" <<< "$FX_LOST"); fi
        [[ -n $FX_LOST ]] || return 0
        ((waited < FX_GUARD_RETRY)) || return 1
        sleep 3
        ((waited += 3))
    done
}

# Refuses to start while the server is already struggling or another fix is running.
fx_gates() {
    local load_x10
    if ((LHA_UID != 0)); then fx_say 'Fixes need root.'; return 1; fi
    # Before the lock: otherwise one refused fix would hold it, and block every fix after it.
    load_x10=$(awk -v l="$R_LOAD1" -v c="$H_CPUS" 'BEGIN { printf "%d", 10 * l / c }')
    if [[ $FX_RISK != low ]] && ((load_x10 >= 40)); then
        fx_say "Load is $R_LOAD1 on $H_CPUS cores. Medium and high risk fixes wait for a quieter moment."
        return 1
    fi
    if ! mkdir "$FX_LOCK" 2>/dev/null; then
        fx_say "Another fix is running. If it crashed: rmdir $FX_LOCK"
        return 1
    fi
    # The menu keeps its own exit trap, which puts the terminal back. It has to survive this one.
    trap "rmdir \"$FX_LOCK\" 2>/dev/null; ${LHA_EXIT_CMD:-:}" EXIT
}

fx_gates_end() {
    rmdir "$FX_LOCK" 2>/dev/null
    if [[ -n ${LHA_EXIT_CMD:-} ]]; then trap "$LHA_EXIT_CMD" EXIT; else trap - EXIT; fi
}

# Low risk: y. Medium and high: the word yes, typed. --yes only ever covers what it names.
fx_confirm() {
    local answer=''
    case $FX_ASSUME:$FX_RISK in
        low:low|medium:low|medium:medium|high:*) return 0 ;;
    esac
    if ! { : </dev/tty; } 2>/dev/null; then
        fx_say "Needs a person to confirm. Skipped. Use --yes=$FX_RISK if you accept this risk."
        return 1
    fi
    if [[ $FX_RISK == low ]]; then
        printf 'Apply this fix? [y/N] ' >/dev/tty
        IFS= read -r answer </dev/tty
        [[ $answer == [yY]* ]]
    else
        printf 'This is %s risk. Type yes to apply: ' "$FX_RISK" >/dev/tty
        IFS= read -r answer </dev/tty
        [[ $answer == yes ]]
    fi
}

# For changes that could lock you out. It runs before the change, because the session can die
# during it. So it reads the undo list when it fires, and a cancel file stops it even if the
# signal comes late: killing its sleep alone would make it run the undo at once.
fx_deadman_start() {
    local script=$FX_DIR/deadman.sh
    {
        printf '#!/bin/bash\nsleep %s\n' "$FX_DEADMAN_SECONDS"
        printf '[[ ! -e %q ]] || exit 0\n' "$FX_DIR/deadman.cancel"
        printf 'awk %q %q | while IFS= read -r line; do bash -c "$line"; done\n' \
            '{ line[NR] = $0 } END { for (i = NR; i > 0; i--) print line[i] }' "$FX_DIR/undo.list"
        printf ': > %q\n' "$FX_DIR/undo.list"
        printf 'echo "$(date) reverted by dead-man timer" >> %q\n' "$FX_DIR/journal.log"
    } > "$script"
    nohup setsid bash "$script" >/dev/null 2>&1 </dev/null &
    FX_DEADMAN_PID=$!
    FX_DEADMAN_AT=$((SECONDS + FX_DEADMAN_SECONDS))
    fx_log "dead-man armed: $FX_DEADMAN_SECONDS s, pid $FX_DEADMAN_PID"
}

fx_deadman_stop() {
    [[ -z $FX_DEADMAN_PID ]] && return 0
    : > "$FX_DIR/deadman.cancel"
    kill "$FX_DEADMAN_PID" 2>/dev/null
    FX_DEADMAN_PID=
    fx_log 'dead-man disarmed'
}

fx_deadman_ask() {
    local answer='' left
    # Stop listening a little before the timer fires, so a late keep cannot pass for a kept change.
    left=$((FX_DEADMAN_AT - SECONDS - 3))
    ((left > 0)) || left=1
    fx_say "Safety timer is running. Unless you confirm within $left seconds, this change undoes itself."
    fx_say 'Open a NEW session to this server now, and check that you can still get in.'
    if [[ ${FX_DEADMAN_AUTO:-} == keep ]]; then fx_deadman_stop; return 0; fi
    if [[ ${FX_DEADMAN_AUTO:-} == wait ]]; then return 1; fi
    if { : </dev/tty; } 2>/dev/null; then
        printf 'New session works? Type keep to keep the change: ' >/dev/tty
        IFS= read -r -t "$left" answer </dev/tty
    fi
    if [[ $answer == keep ]]; then fx_deadman_stop; return 0; fi
    return 1
}

# The whole life of one fix. Returns 0 fixed, 1 failed and rolled back, 2 not applied, 3 guided.
fx_transaction() {
    local id=$1 target=${2:-} name=${1//-/_}
    FX_CAUSE='' FX_RISK=medium FX_MODE=guide FX_LOCKOUT=no FX_EXPECT_GONE=''
    FX_PLAN=() FX_STEPS=() FX_UNDOABLE=yes
    if declare -F "dx_$name" >/dev/null; then "dx_$name" "$target"
    else guide_fallback "$id" "$target"
    fi
    fx_show "$id" "$target"
    if [[ $FX_MODE != auto ]]; then return 3; fi
    if [[ $FX_DRY == yes ]]; then
        fx_say 'Dry run: nothing was changed.'
        return 2
    fi
    fx_gates || return 2
    if ! fx_confirm; then
        fx_say 'Skipped.'
        fx_gates_end
        return 2
    fi
    if ! fx_begin "$id $target"; then
        fx_say 'Could not create a backup folder. Nothing was changed.'
        fx_gates_end
        return 2
    fi
    fx_guard_take
    fx_log "applying $id $target: $FX_CAUSE"
    local status=0 reason=''
    if [[ $FX_LOCKOUT == yes ]]; then fx_deadman_start; fi
    "ap_$name" "$target" || { status=1 reason='the fix did not complete'; }
    if ((status == 0)); then
        sleep "$FX_SETTLE"
        if ! "ck_$name" "$target"; then status=1 reason='the problem is still there after the fix'
        elif ! fx_guard_check; then
            status=1 reason="something else stopped: $(tr '\n' ';' <<< "$FX_LOST")"
        fi
    fi
    if ((status == 0)) && [[ $FX_LOCKOUT == yes ]] && ! fx_deadman_ask; then
        if [[ ${FX_DEADMAN_AUTO:-} == wait ]]; then
            fx_say 'Left to the safety timer.'
            FX_DEADMAN_PID=
            fx_gates_end
            return 1
        fi
        status=1 reason='not confirmed in time'
    fi
    if ((status != 0)); then
        fx_deadman_stop
        fx_rollback
        fx_say "$(badge CRIT) Rolled back: $reason."
        fx_say "Log: $FX_DIR/journal.log"
        fx_gates_end
        return 1
    fi
    fx_deadman_stop
    fx_say "$(badge OK) Fixed. Undo with: --undo $FX_RUN"
    fx_gates_end
    return 0
}

fx_show() {
    local line
    sub "$1${2:+ ($2)}"
    printf '  Cause: %s\n' "${FX_CAUSE:-not determined}"
    case $FX_MODE in
        auto)
            printf '  Risk:  %s\n  Plan:\n' "$FX_RISK"
            for line in "${FX_PLAN[@]}"; do printf '    - %s\n' "$line"; done
            [[ $FX_UNDOABLE == yes ]] || printf '  Note:  part of this cannot be undone.\n' ;;
        *)
            if [[ $FX_MODE == never ]]; then printf '  This tool will not change this for you, on purpose.\n'; fi
            ((${#FX_STEPS[@]} == 0)) || printf '  What to do:\n'
            for line in "${FX_STEPS[@]}"; do printf '    %s\n' "$line"; done ;;
    esac
}

fx_undo_run() {
    local run=$1 dir
    for dir in "$FX_HOME/runs/$run" "/dev/shm/linux-host-audit/$run"; do
        if [[ -f $dir/undo.list ]]; then
            FX_DIR=$dir
            if [[ ! -s $dir/undo.list ]]; then
                fx_say "Nothing to undo in this run: it was undone already, or it could not be undone. $(cat "$dir/what")"
                return 0
            fi
            fx_rollback
            fx_say "Undone: $(cat "$dir/what")"
            return 0
        fi
    done
    fx_say "No such run: $run"
    return 1
}

fx_history() {
    local dir
    for dir in "$FX_HOME"/runs/*; do
        [[ -f $dir/what ]] || continue
        printf '%s  %s\n' "${dir##*/}" "$(cat "$dir/what")"
    done
}
