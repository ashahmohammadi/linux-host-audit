# Command line of the fixer.

fix_usage() {
    cat <<'EOF'
Linux Host Fix: finds the exact cause of each problem, and fixes what is safe to fix.

  bash linux-host-fix.sh --list            Every problem, and how it can be handled
  bash linux-host-fix.sh --diagnose ID     Exact cause and plan. Changes nothing
  bash linux-host-fix.sh --dry-run         Diagnose everything. Changes nothing
  bash linux-host-fix.sh --fix ID[:TARGET] Fix one problem, after asking you
  bash linux-host-fix.sh --fix-all         Offer every automatic fix, one by one
  bash linux-host-fix.sh --undo RUN        Reverse a past fix
  bash linux-host-fix.sh --history         List past fixes

Options: --yes=low or --yes=medium or --yes=high accept fixes up to that risk without asking.

Safety: backups before each change, a test after it, and an automatic rollback if the problem
stays or anything else stopped. Changes that could lock you out undo themselves unless you
confirm from a new session. It never reboots, and never deletes sites, uploads or databases.
EOF
}

fix_mode_of() {
    local id=$1 target=$2 name=${1//-/_}
    FX_CAUSE='' FX_RISK=medium FX_MODE=guide FX_PLAN=() FX_STEPS=() FX_LOCKOUT=no FX_UNDOABLE=yes
    if declare -F "dx_$name" >/dev/null; then "dx_$name" "$target" >/dev/null 2>&1; fi
}

fix_list() {
    local i label
    run_checks
    title 'Problems and how they can be handled'
    for ((i = 0; i < F_N; i++)); do
        fix_mode_of "${F_ID[i]}" "${F_TARGET[i]}"
        case $FX_MODE in
            auto) label="auto, $FX_RISK risk" ;;
            never) label='you decide' ;;
            *) label='steps' ;;
        esac
        printf '  %s  %-26s %-18s %s\n' "$(badge "${F_SEV[i]}")" "${F_ID[i]}${F_TARGET[i]:+:}" "$label" "${F_TITLE[i]}" | cut -c1-110
    done
    ((F_N > 0)) || printf '  %s Nothing to fix.\n' "$(badge OK)"
}

# Finds the finding that matches ID or ID:TARGET.
fix_find() {
    local want=$1 id=${1%%:*} target='' i
    [[ $want != *:* ]] || target=${want#*:}
    for ((i = 0; i < F_N; i++)); do
        [[ ${F_ID[i]} == "$id" ]] || continue
        [[ -z $target || ${F_TARGET[i]} == "$target" ]] || continue
        FOUND_INDEX=$i
        return 0
    done
    return 1
}

fix_one() {
    local i
    run_checks
    if ! fix_find "$1"; then
        fx_say "This problem was not found on this server now: $1"
        return 2
    fi
    i=$FOUND_INDEX
    fx_transaction "${F_ID[i]}" "${F_TARGET[i]}"
}

fix_all() {
    local i count=$((F_N)) status worst=0 first=()
    run_checks
    count=$F_N
    # Disks first: many other fixes need free space. Security last: it can need a person.
    for sev in disk resources services data containers kubernetes web network host jobs security; do
        for ((i = 0; i < count; i++)); do
            [[ ${F_AREA[i]} == "$sev" ]] || continue
            fx_transaction "${F_ID[i]}" "${F_TARGET[i]}"
            status=$?
            ((status != 1)) || worst=1
        done
    done
    return "$worst"
}

fix_main() {
    local action=${1:-} value=${2:-} arg
    local -a words=()
    LHA_LOCALE=${LC_ALL:-${LC_CTYPE:-${LANG:-}}}
    export LC_ALL=C
    PATH=${LHA_TEST_PATH:+$LHA_TEST_PATH:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    PATH+=:/snap/bin:/var/lib/snapd/snap/bin:/var/lib/rancher/rke2/bin:/opt/bin:/run/current-system/sw/bin:/usr/local/apache2/bin
    export PATH
    IFS=$' \t\n'
    set +f
    LHA_UID=${LHA_TEST_UID:-$EUID}
    if [[ -d /dev/shm && -w /dev/shm ]]; then export TMPDIR=/dev/shm; fi
    ui_colors
    for arg in "$@"; do
        case $arg in
            --yes=low|--yes=medium|--yes=high) FX_ASSUME=${arg#--yes=} ;;
            *) words+=("$arg") ;;
        esac
    done
    action=${words[0]:-} value=${words[1]:-}
    if [[ $(uname -s) != Linux && -z ${LHA_TEST_PATH:-} ]]; then fx_say 'This tool requires Linux.'; return 1; fi
    need_awk || return 3
    case $action in
        ''|--help|-h) fix_usage ;;
        --list) fix_list ;;
        --diagnose) FX_DRY=yes; fix_one "$value" ;;
        --dry-run) FX_DRY=yes; fix_all ;;
        --fix) [[ -n $value ]] || { fix_usage; return 2; }; fix_one "$value" ;;
        --fix-all) fix_all ;;
        --undo) fx_undo_run "$value" ;;
        --history) fx_history ;;
        *) fx_say "Unknown argument: $action"; return 2 ;;
    esac
}
