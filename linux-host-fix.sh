#!/usr/bin/env bash
# Linux Host Audit: one command that explains a Linux server from zero to one hundred.
# Read-only: it changes nothing, installs nothing and sends nothing off the server.
# Never prints passwords, process arguments, container environments or Kubernetes secrets.
# Bash 3.2+ on any Linux. Missing tools only hide the part of the report that needs them.

LHA_VERSION=3.6.0
# Lets tests point file checks at a made-up server. Empty on a real one.
LHA_ROOT=${LHA_TEST_ROOT:-}

section() { title "$1"; }
has() { type -P "$1" >/dev/null 2>&1; }

# Without a system database, rpm creates a new one in the home folder.
rpm_usable() {
    has rpm && [[ -n $(ls /var/lib/rpm/Packages* /var/lib/rpm/rpmdb.sqlite \
        /usr/lib/sysimage/rpm/Packages* /usr/lib/sysimage/rpm/rpmdb.sqlite 2>/dev/null) ]]
}

package_snapshot() {
    if has dpkg-query && [[ -r /var/lib/dpkg/status ]]; then
        dpkg-query -W -f='${Status}\t${Package}\t${Version}\n' 2>/dev/null |
            awk -F '\t' '$1 ~ / ok installed$/ { print "dpkg:" $2, $3 }'
    fi
    if rpm_usable; then
        rpm -qa --qf 'rpm:%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null
    fi
    if has apk; then
        # Read installed package metadata, without touching repositories.
        apk info -v 2>/dev/null | awk 'match($0, /-[0-9][^ ]*-r[0-9]+$/) {
            print "apk:" substr($0, 1, RSTART-1), substr($0, RSTART+1)
        }'
    fi
    if has pacman; then
        pacman -Q 2>/dev/null | awk '{print "pacman:" $1, $2}'
    fi
    if [[ -r /var/lib/opkg/status ]]; then
        awk -v RS='' -F '\n' '{
            p=v=s=""
            for (i=1;i<=NF;i++) {
                if ($i ~ /^Package: /) p=substr($i,10)
                if ($i ~ /^Version: /) v=substr($i,10)
                if ($i ~ /^Status: /) s=$i
            }
            if (p != "" && s ~ / ok installed$/) print "opkg:" p, v
        }' /var/lib/opkg/status
    fi
    if [[ -d /nix/store ]]; then
        for profile in /run/current-system/sw "${HOME:-/nonexistent}/.nix-profile"; do
            [[ -d $profile/bin ]] && printf 'nix-profile:%s\n' "$profile"
        done
    fi
    return 0
}

# Evidence goes into shell variables used as a hash table. Pattern matching on these long
# strings took minutes on a cPanel server. Keys are reduced to [A-Za-z0-9_], and every value
# is reduced to plain characters too, because the eval below sees process and package names.
index_evidence() {
    local stale
    for stale in ${!PKG_*} ${!PROC_*} ${!UF_*} ${!AU_*}; do unset "$stale"; done
    pkg_index=$'\n'
    [[ -z $packages ]] || pkg_index+=$(printf '%s\n' "$packages" | awk '{ n = $1; sub(/^[^:]*:/, "", n); print n, $0 }')$'\n'
    units=$'\n'$(printf '%s' "$units" | awk 'NF && !seen[$1]++')$'\n'
    eval "$(printf '%s' "$pkg_index" | awk 'NF {
        k = $1; gsub(/[^A-Za-z0-9_]/, "_", k)
        v = $2 " " $3; gsub(/[^-A-Za-z0-9_.:+~ ]/, "", v)
        print "PKG_" k "=\"" v "\""
    }')"
    eval "$(printf '%s' "$processes" | awk 'NF { k = $0; gsub(/[^A-Za-z0-9_]/, "_", k); print "PROC_" k "=1" }')"
    eval "$(printf '%s' "$units" | awk 'NF >= 2 {
        k = $1; sub(/\.service$/, "", k); gsub(/[^A-Za-z0-9_]/, "_", k)
        v = $2; gsub(/[^-A-Za-z0-9_]/, "", v)
        print "UF_" k "=\"" v "\""
    }')"
    eval "$(printf '%s' "$active_units" | awk 'NF >= 4 {
        k = $1; sub(/\.service$/, "", k); gsub(/[^A-Za-z0-9_]/, "_", k)
        v = $2 " " $3 " " $4; gsub(/[^-A-Za-z0-9_ ]/, "", v)
        print "AU_" k "=\"" v "\""
    }')"
}

# Sets REPLY instead of printing: signatures run hundreds of lookups, so no subshells here.
package_matches() {
    local pattern=$1 prefix rest name record
    REPLY=
    case $pattern in
        *'*'*|*'?'*|*'['*)
            prefix=${pattern%%[*?[]*}
            while read -r name record; do
                # shellcheck disable=SC2053 # the pattern is a glob on purpose
                if [[ $name == $pattern ]]; then REPLY=$record; return 0; fi
            done <<< "$(grep "^$prefix" <<< "$pkg_index")"
            ;;
        *)
            rest=PKG_${pattern//[!A-Za-z0-9_]/_}
            REPLY=${!rest:-}
            ;;
    esac
}

# Sets REPLY to the first match on PATH, also without a subshell.
find_binary() {
    local dir rest=$PATH:
    REPLY=
    while [[ -n $rest ]]; do
        dir=${rest%%:*} rest=${rest#*:}
        if [[ -n $dir && -f $dir/$1 && -x $dir/$1 ]]; then REPLY=$dir/$1; return 0; fi
    done
    return 1
}

sig_group() {
    sig_current=$1
    sig_groups+="$1"$'\n'
}

detect() {
    local label=$1 binaries=$2 paths=$3 patterns=$4 services=$5
    local item path record load state rest status key text=''
    local installed=0 footprint=0 running=0
    local -a evidence=() binary_list path_list pattern_list service_list
    read -r -a binary_list <<< "$binaries"
    read -r -a path_list <<< "$paths"
    read -r -a pattern_list <<< "$patterns"
    read -r -a service_list <<< "$services"

    for item in "${binary_list[@]}"; do
        if find_binary "$item"; then
            evidence+=("binary=$REPLY")
            installed=1
        fi
    done

    for item in "${path_list[@]}"; do
        for path in $item; do
            [[ -e $path || -L $path ]] || continue
            evidence+=("path=$path")
            if [[ -f $path && -x $path ]]; then installed=1; else footprint=1; fi
            break
        done
    done

    for item in "${pattern_list[@]}"; do
        package_matches "$item"
        if [[ -n $REPLY ]]; then
            evidence+=("package=$REPLY")
            installed=1
        fi
    done

    for item in "${service_list[@]}"; do
        key=${item//[!A-Za-z0-9_]/_}
        path=PROC_$key
        if [[ -n ${!path:-} ]]; then
            evidence+=("process=$item")
            running=1
        fi
        path=UF_$key
        record=AU_$key
        if [[ -n ${!path:-} ]]; then
            evidence+=("unit=$item.service (${!path})")
            footprint=1
        fi
        if [[ -n ${!path:-} || -n ${!record:-} ]]; then
            if [[ $diagnostic_units != *$'\n'"$item.service"$'\n'* ]]; then
                diagnostic_units+="$item.service"$'\n'
            fi
        fi
        if [[ -n ${!record:-} ]]; then
            read -r load state rest <<< "${!record}"
            if [[ $load == loaded && $state == active ]]; then
                evidence+=("systemd=active/${rest%% *}")
                if [[ $rest == running || $rest == running\ * ]]; then running=1; else footprint=1; fi
            fi
        fi
    done

    if (( running )); then status=RUNNING
    elif (( installed )); then status=PRESENT
    elif (( footprint )); then status=TRACE
    else status=NOT-DETECTED
    fi
    if (("${#evidence[@]}")); then printf -v text ' %s;' "${evidence[@]}"; fi
    sig_rows+="$sig_current|$label|$status|$text"$'\n'
}

service_report() {
    local unit data key value load active sub boot result code status condition assertion
    local trigger changed type restarts pid reason invocation hints condition_time assert_time source trigger_state
    section 'Service runtime and stop diagnostics'
    if [[ $systemd_visible != yes ]]; then
        if has rc-status && [[ -d /run/openrc || -d /lib/rc/init.d ]]; then
            if rc-status --nocolor --servicelist 2>/dev/null; then
                printf '%s\n' 'OpenRC status shown above. Stop causes require service or supervisor logs.'
                return 0
            fi
        fi
        printf '%s\n' 'Service manager runtime unavailable. Process and file evidence is shown above.'
        return 0
    fi
    while IFS= read -r unit; do
        [[ -n $unit ]] || continue
        printf '\n%s\n' "$unit"
        if ! data=$(systemctl --system show --no-pager \
            -p LoadState -p ActiveState -p SubState -p UnitFileState -p Result \
            -p ExecMainCode -p ExecMainStatus -p MainPID -p NRestarts -p Type \
            -p ConditionResult -p AssertResult -p ConditionTimestamp -p AssertTimestamp -p TriggeredBy -p InvocationID \
            -p StateChangeTimestamp -p ExecMainExitTimestamp -- "$unit" 2>/dev/null); then
            printf '  Runtime details unavailable\n'
            continue
        fi
        load= active= sub= boot= result= code= status= condition= assertion=
        trigger= changed= type= restarts= pid= invocation= condition_time= assert_time=
        while IFS='=' read -r key value; do
            case $key in
                LoadState) load=$value ;;
                ActiveState) active=$value ;;
                SubState) sub=$value ;;
                UnitFileState) boot=$value ;;
                Result) result=$value ;;
                ExecMainCode) code=$value ;;
                ExecMainStatus) status=$value ;;
                MainPID) pid=$value ;;
                NRestarts) restarts=$value ;;
                Type) type=$value ;;
                TriggeredBy) trigger=$value ;;
                InvocationID) invocation=$value ;;
                ConditionTimestamp) condition_time=$value ;;
                AssertTimestamp) assert_time=$value ;;
                StateChangeTimestamp) changed=$value ;;
                ExecMainExitTimestamp) [[ -z $value ]] || printf '  Main process exited: %s\n' "$value" ;;
                ConditionResult) condition=$value ;;
                AssertResult) assertion=$value ;;
            esac
        done <<< "$data"
        printf '  Runtime=%s/%s  Load=%s  Startup=%s  PID=%s  Restarts=%s\n' \
            "${active:-unknown}" "${sub:-unknown}" "${load:-unknown}" "${boot:-unknown}" \
            "${pid:-unknown}" "${restarts:-unknown}"
        printf '  Result=%s  MainExitCodeKind=%s  MainExitStatus=%s\n' \
            "${result:-unknown}" "${code:-unknown}" "${status:-unknown}"
        if [[ -n $trigger ]]; then
            printf '  Activation units: %s\n' "$trigger"
            if [[ $active == inactive ]]; then
                for source in $trigger; do
                    case $source in
                        *.socket|*.timer|*.path)
                            trigger_state=$(systemctl --system is-active -- "$source" 2>/dev/null) || :
                            printf '  Activation state: %s=%s\n' "$source" "${trigger_state:-unknown}"
                            ;;
                    esac
                done
            fi
        fi
        [[ -z $changed ]] || printf '  State changed: %s\n' "$changed"

        case $load:$boot in
            masked:*|*:masked|*:masked-runtime) printf '  Start blocker: unit is masked\n' ;;
            bad-setting:*|error:*) printf '  Start blocker: systemd could not load the unit correctly\n' ;;
            not-found:*) printf '  Start blocker: systemd cannot find the unit definition\n' ;;
        esac
        case $active/$sub in
            active/running) continue ;;
            active/exited)
                if [[ $type == oneshot ]]; then printf '  One-shot completed and remains active\n'
                else printf '  Unit remains active after its main command exited\n'; fi
                continue ;;
            */auto-restart|*/auto-restart-queued) printf '  Automatic restart pending\n' ;;
            activating/*|deactivating/*|reloading/*|refreshing/*)
                printf '  Transition in progress\n' ;;
        esac
        if [[ $condition == no && -n $condition_time ]]; then
            printf '  Last condition check failed at %s (start may be skipped)\n' "$condition_time"
        fi
        if [[ $assertion == no && -n $assert_time ]]; then
            printf '  Last assertion failed at %s (start may be rejected)\n' "$assert_time"
        fi
        if [[ $code == 2 || $code == 3 ]] && [[ $status =~ ^[1-9][0-9]*$ ]]; then
            printf '  Main process signal: %s\n' "$(kill -l "$status" 2>/dev/null || printf '%s' "$status")"
        fi

        reason=
        case $result in
            exit-code) reason='A service command exited with a failure status' ;;
            signal) reason='A service process was terminated by a signal' ;;
            core-dump) reason='A service process terminated with a core dump' ;;
            watchdog) reason='The service missed its watchdog deadline' ;;
            timeout) reason='A service operation timed out' ;;
            oom-kill) reason='An out-of-memory kill affected the service' ;;
            start-limit-hit) reason='systemd blocked starts after the rate limit was reached' ;;
            resources) reason='systemd recorded a resource or setup failure' ;;
            protocol) reason='The service failed the expected startup protocol' ;;
            exec-condition) reason='ExecCondition prevented service startup' ;;
            dependency) reason='A dependency failed' ;;
            success|'') ;;
            *) reason="systemd recorded result $result" ;;
        esac
        if [[ -n $reason ]]; then
            printf '  Last recorded failure: %s\n' "$reason"
            if [[ $result == exit-code && $code == 1 ]]; then
                case $status in
                    200) printf '  Exit mapping: CHDIR (working directory setup failed)\n' ;;
                    203) printf '  Exit mapping: EXEC (executable or interpreter could not run)\n' ;;
                    216) printf '  Exit mapping: GROUP (group credentials setup failed)\n' ;;
                    217) printf '  Exit mapping: USER (user credentials or namespace setup failed)\n' ;;
                    226) printf '  Exit mapping: NAMESPACE (namespace setup failed)\n' ;;
                esac
            fi
        elif [[ $active == inactive || $active == failed ]]; then
            printf '  Stop cause: unknown from current service metadata\n'
        fi
        if [[ $invocation =~ ^[a-fA-F0-9]{32}$ && $invocation != 00000000000000000000000000000000 ]] &&
            has journalctl && has awk; then
            hints=$(journalctl --system -b -n 80 --no-pager -o cat \
                "_SYSTEMD_INVOCATION_ID=$invocation" 2>/dev/null | awk '
                {
                    msg=tolower($0)
                    if (msg ~ /address already in use|eaddrinuse/) bind=1
                    if (msg ~ /permission denied|operation not permitted/) perm=1
                    if (msg ~ /no space left on device|disk quota exceeded/) space=1
                    if (msg ~ /read-only file system/) ro=1
                    if (msg ~ /no such file or directory/) missing=1
                    if (msg ~ /syntax error|invalid configuration|configuration test failed/) config=1
                }
                END {
                    if (bind) print "address already in use"
                    if (perm) print "permission or operation denied"
                    if (space) print "storage space or quota exhausted"
                    if (ro) print "read-only filesystem"
                    if (missing) print "missing file or directory"
                    if (config) print "configuration or syntax error"
                }') || hints=
            if [[ -n $hints ]]; then
                while IFS= read -r value; do
                    printf '  Journal clue for recorded invocation: %s\n' "$value"
                done <<< "$hints"
            fi
        fi
        if [[ $journal == yes ]] && has journalctl; then
            printf '  Recent current-boot journal (historical context):\n'
            journalctl --system -b -u "$unit" -n 20 --no-pager -o short-iso 2>/dev/null ||
                printf '  Journal unavailable or access denied\n'
        fi
    done <<< "$diagnostic_units"
}

cache_directives() {
    local label=$1 pattern=$2 exclude=$3 file count=0 denied=0 found=0
    shift 3
    for file in "$@"; do
        [[ -f $file ]] || continue
        if [[ ! -r $file ]]; then ((denied+=1)); continue; fi
        ((count+=1))
        if awk -v pattern="$pattern" -v exclude="$exclude" '
            {
                line=tolower($0)
                if (line ~ pattern && (exclude == "" || line !~ exclude)) {
                    found=1
                    exit
                }
            }
            END { exit !found }
        ' "$file" 2>/dev/null; then
            printf '%-32s CONFIG-FOUND  %s\n' "$label" "$file"
            found=1
        fi
    done
    if (( ! found )); then
        printf '%-32s %s\n' "$label" "No matching directive in $count readable files"
    fi
    if (( denied )); then printf '  %s unreadable candidate files\n' "$denied"; fi
    return 0
}

host_report() {
    local release=/etc/os-release line os='' pid1='' virt
    [[ -r $release ]] || release=/usr/lib/os-release
    if [[ -r $release ]]; then
        while IFS= read -r line; do
            if [[ $line == PRETTY_NAME=* ]]; then
                os=${line#*=}
                os=${os#\"}
                os=${os%\"}
                break
            fi
        done < "$release"
    fi
    if [[ -r /proc/1/comm ]]; then IFS= read -r pid1 < /proc/1/comm; fi
    printf 'OS: %s\nKernel and architecture: %s\nPID 1: %s\n' "${os:-unknown}" "$(uname -rm)" "${pid1:-unknown}"
    if has systemd-detect-virt; then
        virt=$(systemd-detect-virt 2>/dev/null) || :
        printf 'Virtualization: %s\n' "${virt:-unknown}"
    elif [[ -f /.dockerenv ]]; then
        printf 'Virtualization: Docker marker found\n'
    elif [[ -f /run/.containerenv ]]; then
        printf 'Virtualization: container marker found\n'
    fi
    if [[ -r /proc/meminfo ]]; then awk '/^MemTotal:|^MemAvailable:|^SwapTotal:/ { print }' /proc/meminfo; fi
    if has getconf; then printf 'Online CPUs: %s\n' "$(getconf _NPROCESSORS_ONLN 2>/dev/null)"; fi
    if has df; then
        if has timeout; then timeout 5 df -hPl / 2>/dev/null || :
        else df -hP / 2>/dev/null || :; fi
    fi
    if (( EUID != 0 )); then printf 'Access: unprivileged (restricted paths and processes may be hidden)\n'
    else printf 'Access: root\n'
    fi
}

# Extend diagnostics from the existing manager snapshot without probing each unit.
collect_extra_systemd_units() {
    local unit load active sub service
    [[ $systemd_visible == yes ]] || return 0
    while read -r unit load active sub; do
        [[ $unit == *.service ]] || continue
        [[ $diagnostic_units != *$'\n'"$unit"$'\n'* ]] || continue
        service=${unit%.service}
        if [[ $active != failed ]]; then
            case $service in
                *@*)
                    [[ $diagnostic_units == *$'\n'"${service%%@*}.service"$'\n'* ||
                       $service == postgresql@* || $service == redis@* ||
                       $service == clamd@* || $service == openvpn-*@* ]] || continue
                    ;;
                php[0-9]*-fpm|php-fpm[0-9]*|ea-php[0-9]*-php-fpm|plesk-php[0-9]*-fpm|alt-php[0-9]*-php-fpm|postgresql-[0-9]*) ;;
                *) continue ;;
            esac
        fi
        diagnostic_units+="$unit"$'\n'
    done <<< "$active_units"
}

service_extra() {
    local dir previous duplicate output svstat= runit=no s6=no shown=no
    local -a seen=()

    if [[ $processes == *$'\n'runsvdir$'\n'* || $processes == *$'\n'runsv$'\n'* ]] && has sv; then
        runit=yes
    fi
    if [[ $processes == *$'\n's6-svscan$'\n'* || $processes == *$'\n's6-supervise$'\n'* ]]; then
        svstat=$(type -P s6-svstat) || :
        if [[ -z $svstat && -x /command/s6-svstat ]]; then svstat=/command/s6-svstat; fi
        [[ -z $svstat ]] || s6=yes
    fi
    [[ $runit == yes || $s6 == yes ]] || return 0
    section 'runit and s6 supervisor runtime'
    for dir in /var/service/* /service/* /run/service/* /run/runit/service/* /etc/service/*; do
        [[ -d $dir && -f $dir/supervise/status && -r $dir/supervise/status ]] || continue
        duplicate=no
        for previous in "${seen[@]}"; do
            if [[ $dir -ef $previous ]]; then duplicate=yes; break; fi
        done
        [[ $duplicate == no ]] || continue
        seen+=("$dir")
        if [[ $s6 == yes ]] && output=$("$svstat" "$dir" 2>/dev/null) && [[ -n $output ]]; then
            printf 's6 %q: %s\n' "${dir##*/}" "$output"
        elif [[ $runit == yes ]] && output=$(sv status "$dir" 2>/dev/null) && [[ $output == run:* || $output == down:* || $output == finish:* ]]; then
            printf 'runit %q: %s\n' "${dir##*/}" "${output//"$dir"/service}"
        else
            continue
        fi
        shown=yes
    done
    if [[ $shown == yes ]]; then
        printf '%s\n' 'Supervisor state is a snapshot. Check service logs for the reason behind an unexpected exit.'
    else
        printf '%s\n' 'Supervisor process observed. No readable live service status in standard supervision directories.'
    fi
}

metrics_snapshot() {
    local uptime rest whole fraction now=0 elapsed name path slave
    local user nice system idle wait irq softirq steal total busy dt db
    local sd wd old_avail=0 key value available='' memory='' link route='' disk_rows='' net_rows='' rates
    local a b read_sectors d e f write_sectors rx tx
    steal_pct=0 wait_pct=0 cpu_pct=-1 ram_pct=-1 disk_read=-1 disk_write=-1 net_rx=-1 net_tx=-1
    metrics_disk_scope='whole leaf block devices'
    metrics_net_scope='no eligible interface'

    if [[ -r /proc/uptime ]] && read -r uptime rest < /proc/uptime &&
        [[ $uptime =~ ^([0-9]+)\.([0-9][0-9])$ ]]; then
        whole=${BASH_REMATCH[1]}
        fraction=${BASH_REMATCH[2]}
        now=$((10#$whole * 100 + 10#$fraction))
    fi
    elapsed=$((now - ${metrics_time:-now}))

    if [[ -r /proc/stat ]] && read -r name user nice system idle wait irq softirq steal rest < /proc/stat &&
        [[ $name == cpu && $user =~ ^[0-9]+$ ]]; then
        # user and nice already include guest time. Treat idle and iowait as non-busy.
        busy=$((user + nice + system + irq + softirq + steal))
        total=$((busy + idle + wait))
        dt=$((total - ${metrics_cpu_total:-total}))
        db=$((busy - ${metrics_cpu_busy:-busy}))
        if ((dt > 0 && db >= 0 && db <= dt)); then cpu_pct=$(((100 * db + dt / 2) / dt)); fi
        sd=$((steal - ${metrics_cpu_steal:-steal})) wd=$((wait - ${metrics_cpu_wait:-wait}))
        if ((dt > 0)); then steal_pct=$((100 * sd / dt)) wait_pct=$((100 * wd / dt)); fi
        metrics_cpu_total=$total metrics_cpu_busy=$busy metrics_cpu_steal=$steal metrics_cpu_wait=$wait
    else
        unset metrics_cpu_total metrics_cpu_busy
    fi
    if [[ -r /proc/meminfo ]]; then
        while read -r key value rest; do
            case $key in
                MemTotal:) memory=$value ;;
                MemAvailable:) available=$value ;;
                MemFree:|Buffers:|Cached:) old_avail=$((old_avail + value)) ;;
            esac
            [[ -z $memory || -z $available ]] || break
        done < /proc/meminfo
        [[ -n $available ]] || available=$old_avail
        if [[ $memory =~ ^[0-9]+$ && $available =~ ^[0-9]+$ ]] &&
            ((memory > 0 && available <= memory)); then
            ram_pct=$(((100 * (memory - available) + memory / 2) / memory))
        fi
    fi

    for path in /sys/block/*; do
        [[ -r $path/stat ]] || continue
        name=${path##*/}
        case $name in loop*|ram*|zram*|fd*) continue ;; esac
        # Stacked devices report I/O that may already appear on their backing devices.
        for slave in "$path"/slaves/*; do [[ ! -e $slave ]] || continue 2; done
        if read -r a b read_sectors d e f write_sectors rest < "$path/stat" &&
            [[ $read_sectors =~ ^[0-9]+$ && $write_sectors =~ ^[0-9]+$ ]]; then
            disk_rows+="disk $name $read_sectors $write_sectors"$'\n'
        fi
    done

    if has awk && [[ -r /proc/net/route ]]; then
        route=$(awk 'NR > 1 && $2 == "00000000" && substr($4, length($4), 1) ~ /[13579bBdDfF]/ {
            if (!found || $7 + 0 < metric) { dev=$1; metric=$7 + 0; found=1 }
        } END { print dev }' /proc/net/route)
    fi
    if [[ -z $route ]] && has awk && [[ -r /proc/net/ipv6_route ]]; then
        route=$(awk '$1 == "00000000000000000000000000000000" && $2 == "00" &&
            $3 == "00000000000000000000000000000000" && $4 == "00" && $10 != "lo" &&
            substr($9, length($9), 1) ~ /[13579bBdDfF]/ {
            if (!found || ("x" $6) < metric) { dev=$10; metric="x" $6; found=1 }
        } END { print dev }' /proc/net/ipv6_route)
    fi
    if [[ -n $route && $route != lo ]]; then
        metrics_net_scope="default route: $route"
    else
        route=''
        metrics_net_scope='hardware-backed interfaces'
    fi
    for path in /sys/class/net/*; do
        name=${path##*/}
        [[ $name != lo && -r $path/statistics/rx_bytes && -r $path/statistics/tx_bytes ]] || continue
        if [[ -n $route ]]; then
            [[ $name == "$route" ]] || continue
        else
            [[ -e $path/device ]] || continue
        fi
        if { read -r rx < "$path/statistics/rx_bytes" && read -r tx < "$path/statistics/tx_bytes"; } 2>/dev/null &&
            [[ $rx =~ ^[0-9]+$ && $tx =~ ^[0-9]+$ ]]; then
            net_rows+="net $name $rx $tx"$'\n'
        fi
    done
    if [[ -z $net_rows && -z $route && -r /proc/net/dev ]] && has awk; then
        # In isolated namespaces the visible interface can be virtual and have no PCI device.
        net_rows=$(awk 'NR > 2 {
            line=$0; sub(/^[ \t]+/, "", line)
            split(line,f,/[: \t]+/)
            if (f[1] != "lo" && f[2] ~ /^[0-9]+$/ && f[10] ~ /^[0-9]+$/) {
                print "net", f[1], f[2], f[10]; count++
            }
        } END { if (count != 1) exit 1 }' /proc/net/dev) || net_rows=''
        if [[ -n $net_rows ]]; then metrics_net_scope='single visible non-loopback interface'; fi
    fi
    [[ -n $net_rows ]] || metrics_net_scope='no eligible interface'
    [[ -n $disk_rows ]] || metrics_disk_scope='no eligible block device'

    if ((elapsed > 0)) && has awk; then
        rates=$(
            printf '%s\n' "${metrics_previous:-}" '---' "$disk_rows" "$net_rows" |
                awk -v elapsed="$elapsed" '
                    $1 == "---" { current=1; next }
                    NF != 4 { next }
                    !current {
                        key=$1 SUBSEP $2
                        first[key]=$3; second[key]=$4; old_count[$1]++
                        next
                    }
                    {
                        key=$1 SUBSEP $2
                        new_count[$1]++
                        if (!(key in first) || $3 < first[key] || $4 < second[key]) bad[$1]=1
                        else {
                            delta_a[$1]+=$3-first[key]
                            delta_b[$1]+=$4-second[key]
                        }
                    }
                    function rates(type, units) {
                        if (!new_count[type] || old_count[type] != new_count[type] || bad[type]) {
                            printf "-1 -1 "
                        } else {
                            printf "%.0f %.0f ", delta_a[type]*units*100/elapsed, delta_b[type]*units*100/elapsed
                        }
                    }
                    END { rates("disk",512); rates("net",1); print "" }
                '
        ) || rates=''
        if [[ -n $rates ]]; then read -r disk_read disk_write net_rx net_tx <<< "$rates"; fi
    fi
    metrics_previous="$disk_rows"$'\n'"$net_rows"
    metrics_time=$now
}

metric_inventory() {
    local path value name
    section 'Host resources'
    host_report
    section 'Kernel counters'
    printf '%s\n' 'Values reflect the kernel views visible to this process. Container limits are shown separately.'
    for path in /proc/uptime /proc/loadavg /proc/meminfo /proc/pressure/{cpu,memory,io} /proc/net/dev /proc/net/sockstat /proc/net/snmp /proc/diskstats /proc/mdstat /proc/sys/fs/file-nr; do
        [[ -r $path ]] || continue
        printf '\n%s\n' "$path"
        cat "$path" 2>/dev/null || :
    done
    if [[ -r /proc/stat ]] && has awk; then
        printf '\nCPU time counters (including per CPU)\n'
        awk '/^cpu[0-9]* / || /^(ctxt|intr|processes|procs_running|procs_blocked) / { print $1 == "intr" ? $1 " " $2 : $0 }' /proc/stat
    fi
    section 'Selected VM and paging counters'
    if [[ -r /proc/vmstat ]] && has awk; then
        awk '$1 ~ /^(pgpgin|pgpgout|pswpin|pswpout|pgfault|pgmajfault|oom_kill|nr_dirty|nr_writeback|numa_hit|numa_miss)$/ { print }' /proc/vmstat
    fi
    section 'Visible cgroup v2 limits and usage'
    local group_path='/sys/fs/cgroup' group
    if [[ -r /proc/self/cgroup ]]; then
        while IFS=: read -r name value group; do
            if [[ $name == 0 && -z $value && $group == /* && $group != *..* &&
                  -r /sys/fs/cgroup${group%/}/cgroup.controllers ]]; then
                group_path=/sys/fs/cgroup${group%/}
            fi
        done < /proc/self/cgroup
    fi
    if [[ -r $group_path/cgroup.controllers ]]; then
        printf 'Counter path: %q\n' "$group_path"
        for name in cpu.max cpu.stat cpuset.cpus.effective memory.current memory.high memory.max \
            memory.events memory.swap.current memory.swap.max io.stat pids.current pids.max; do
            path=$group_path/$name
            [[ -r $path ]] || continue
            printf '\n%s\n' "$name"
            cat "$path" 2>/dev/null || :
        done
    else
        printf 'cgroup v2 counters unavailable\n'
    fi
    section 'Filesystem capacity and inodes'
    if has df; then
        if has timeout; then timeout 5 df -hPl 2>/dev/null || :; timeout 5 df -iPl 2>/dev/null || :
        else df -hP / 2>/dev/null || :; df -iP / 2>/dev/null || :; fi
    fi
    if has lsblk; then
        section 'Block devices'
        lsblk -o NAME,TYPE,SIZE,ROTA,RO,FSTYPE 2>/dev/null || :
    fi
    if has ip; then
        section 'Network interfaces and addresses'
        ip -brief address show 2>/dev/null || :
    fi
    section 'Thermal zones (millidegrees Celsius)'
    for path in /sys/class/thermal/thermal_zone*; do
        [[ -r $path/type && -r $path/temp ]] || continue
        if { read -r name < "$path/type" && read -r value < "$path/temp"; } 2>/dev/null; then
            printf '%s %s %s\n' "${path##*/}" "$name" "$value"
        fi
    done
    return 0
}

# Java, Erlang and Python services all share one process name. Their main class or module says
# what they are. Arguments can hold passwords, so each is only compared here, and never kept.
runtime_role() {
    local arg count=0
    REPLY=
    while IFS= read -r -d '' arg; do
        ((count += 1))
        ((count <= 400)) || break
        case $arg in
            org.apache.catalina.startup.Bootstrap) REPLY=tomcat; break ;;
            kafka.Kafka) REPLY=kafka; break ;;
            org.apache.zookeeper.server.quorum.QuorumPeerMain) REPLY=zookeeper; break ;;
            org.apache.cassandra.service.CassandraDaemon) REPLY=cassandra; break ;;
            org.elasticsearch.bootstrap.Elasticsearch) REPLY=elasticsearch; break ;;
            org.opensearch.bootstrap.OpenSearch) REPLY=opensearch; break ;;
            io.confluent.ksql.rest.server.KsqlServerMain) REPLY=ksql; break ;;
            org.apache.activemq.console.Main|*/activemq.jar) REPLY=activemq; break ;;
            -Dsolr.*) REPLY=solr; break ;;
            org.logstash.Logstash) REPLY=logstash; break ;;
            org.neo4j.server.*) REPLY=neo4j; break ;;
            org.sonar.application.App) REPLY=sonarqube; break ;;
            org.jboss.modules.Main|*/jboss-modules.jar) REPLY=wildfly; break ;;
            rabbit|*/rabbit-[0-9]*) REPLY=rabbitmq-server; break ;;
            */gunicorn|gunicorn|gunicorn.app.*) REPLY=gunicorn; break ;;
            */uvicorn|uvicorn) REPLY=uvicorn; break ;;
            */celery|celery) REPLY=celery; break ;;
        esac
    done 2>/dev/null < "$1"
}

scan_evidence() {
    local proc comm exe result
    systemd_visible=no diagnostic_units=$'\n' sig_rows='' sig_groups='' sig_current=''
    packages=$(package_snapshot)
    processes=$'\n'
    # /proc comm is limited to 15 bytes. Supplement truncated names via /proc/exe when readable.
    for proc in /proc/[0-9]*/comm; do
        if { IFS= read -r comm < "$proc"; } 2>/dev/null; then
            processes+="$comm"$'\n'
            if (( ${#comm} == 15 )) && has readlink; then
                exe=$(readlink "${proc%/comm}/exe" 2>/dev/null) || :
                exe=${exe##*/}
                exe=${exe% (deleted)}
                [[ -z $exe ]] || processes+="$exe"$'\n'
            fi
            case $comm in
                java|beam.smp|python*)
                    runtime_role "${proc%/comm}/cmdline"
                    [[ -z $REPLY ]] || processes+="$REPLY"$'\n' ;;
            esac
        fi
    done
    if [[ $processes == $'\n' ]] && has ps; then
        processes+=$(ps -eo comm= 2>/dev/null)
        processes+=$'\n'
    fi
    units=$'\n'
    active_units=$'\n'
    if [[ -d /run/systemd/system || -n ${LHA_TEST_PATH:-} ]] && has systemctl; then
        if result=$(systemctl --system list-unit-files --type=service --no-legend --no-pager 2>/dev/null); then
            units+=$(awk 'NF >= 2 {print $1, $2}' <<< "$result")
            units+=$'\n'
        fi
        if result=$(systemctl --system list-units --type=service --all --plain --no-legend --no-pager 2>/dev/null); then
            active_units+=$(awk 'NF >= 4 {print $1, $2, $3, $4}' <<< "$result")
            active_units+=$'\n'
            systemd_visible=yes
        fi
    fi
    for proc in /etc/init.d/* /etc/systemd/system/*.service /usr/lib/systemd/system/*.service /lib/systemd/system/*.service; do
        [[ -f $proc || -L $proc ]] || continue
        comm=${proc##*/}
        [[ $proc != /etc/init.d/* ]] || comm+=.service
        units+="$comm file-found"$'\n'
    done
    index_evidence
    signatures
    collect_extra_systemd_units
}

# Signatures describe host-side evidence. Shared binaries use family-level labels.
signatures() {
sig_group 'Hosting panels'
detect 'cPanel & WHM' 'whmapi1 uapi' '/usr/local/cpanel/cpanel /usr/local/cpanel/version' 'cpanel' 'cpanel cpsrvd'
detect 'Plesk' 'plesk' '/usr/local/psa/version /opt/psa/version /etc/psa/psa.conf' 'psa plesk-core' 'psa sw-cp-server'
detect 'DirectAdmin' 'directadmin' '/usr/local/directadmin/directadmin /usr/local/directadmin/conf/directadmin.conf' 'directadmin' 'directadmin'
detect 'CyberPanel' 'cyberpanel' '/usr/local/CyberCP/manage.py /usr/local/CyberCP/CyberCP/settings.py' 'cyberpanel' 'lscpd'
detect 'aaPanel / BaoTa' '' '/www/server/panel/BT-Panel /www/server/panel/BT-Task' '' 'bt BT-Panel BT-Task'
detect 'HestiaCP' '' '/usr/local/hestia/bin/v-list-users /usr/local/hestia/conf/hestia.conf' 'hestia' 'hestia'
detect 'VestaCP' '' '/usr/local/vesta/bin/v-list-users /usr/local/vesta/conf/vesta.conf' 'vesta' 'vesta'
detect 'CloudPanel' 'clpctl' '/usr/bin/clpctl /usr/local/bin/clpctl' 'cloudpanel' ''
detect 'Control Web Panel (CWP)' '' '/usr/local/cwpsrv/bin/cwpsrv /usr/local/cwp/.conf' '' 'cwpsrv cwp-phpfpm'
detect 'ISPConfig' '' '/usr/local/ispconfig/server/server.sh /usr/local/ispconfig/interface/web/index.php' '' ''
detect 'Webmin' '' '/etc/webmin/miniserv.conf /usr/share/webmin/miniserv.pl /usr/libexec/webmin/miniserv.pl' 'webmin' 'webmin'
detect 'Virtualmin' 'virtualmin' '/usr/share/webmin/virtual-server /usr/libexec/webmin/virtual-server /etc/webmin/virtual-server/config' 'webmin-virtual-server' ''
detect 'Usermin' '' '/etc/usermin/miniserv.conf' 'usermin' 'usermin'
detect 'InterWorx' '' '/usr/local/interworx/bin/nodeworx.pex /home/interworx/iworx.ini' 'interworx' 'iworx'
detect 'Froxlor' 'froxlor-cli' '/var/www/froxlor/bin/froxlor-cli /etc/froxlor' 'froxlor' ''
detect 'FASTPANEL' 'mogwai' '/usr/local/bin/mogwai /usr/local/fastpanel2/fastpanel2' 'fastpanel2' 'fastpanel2'
detect 'RunCloud agent' 'runcloud-agent' '/etc/runcloud /opt/RunCloud' 'runcloud-agent' 'runcloud-agent'
detect 'ServerPilot agent' '' '/etc/serverpilot /opt/sp/bin/serverpilot-agent' 'serverpilot-agent' 'serverpilot-agent'
detect 'Enhance app controller' 'appcd' '/usr/local/bin/appcd' '' 'appcd'
detect 'ApisCP' 'cpcmd' '/usr/local/apnscp/bin/cpcmd' '' 'apiscp'
detect 'Sentora' '' '/etc/sentora/configs /etc/sentora/panel/index.php' '' ''
detect 'ISPmanager' '' '/usr/local/mgr5/etc/ispmgr.conf /usr/local/mgr5/etc/ispmgr.db' 'ispmanager*' ''
detect 'Ajenti' 'ajenti-panel' '/etc/ajenti/config.yml' 'ajenti-panel' 'ajenti'
detect 'Cockpit' 'cockpit-bridge' '/etc/cockpit/cockpit.conf /usr/lib/cockpit/cockpit-ws /usr/libexec/cockpit-ws' 'cockpit-ws' 'cockpit cockpit-ws'
detect 'Pterodactyl Wings' 'wings' '/etc/pterodactyl/config.yml' '' 'wings'
detect 'AMP game server manager' 'ampinstmgr' '/opt/cubecoders/amp/ampinstmgr' 'ampinstmgr' 'ampinstmgr'
detect 'YunoHost' 'yunohost' '/etc/yunohost/current_host' 'yunohost' 'yunohost-api'
detect 'YunoHost SSO' '' '' 'ssowat' ''
detect 'Cloudron host' '' '/home/yellowtent/box /etc/systemd/system/box.service' '' ''
detect 'Dokku' 'dokku' '/var/lib/dokku/plugins/available' 'dokku' ''
detect '1Panel' '1pctl' '/opt/1panel /usr/local/bin/1panel' '' '1panel 1panel-core 1panel-agent'

sig_group 'Web and app runtimes'
detect 'Nginx' 'nginx' '/etc/nginx/nginx.conf /www/server/nginx/sbin/nginx /usr/local/nginx/sbin/nginx' 'nginx nginx-core nginx-full nginx-light nginx-extras ea-nginx' 'nginx'
detect 'Apache HTTP Server' 'httpd apache2 apache2ctl apachectl' '/etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /www/server/apache/bin/httpd /usr/local/apache/bin/httpd' 'httpd apache2 ea-apache24' 'httpd apache2'
detect 'LiteSpeed server family' 'lshttpd lswsctrl' '/usr/local/lsws/bin/lshttpd /usr/local/lsws/bin/lswsctrl' '' 'lsws lshttpd litespeed'
detect 'LiteSpeed commercial edition license artifacts' '' '/usr/local/lsws/conf/license.key /usr/local/lsws/conf/serial.no /usr/local/lsws/conf/trial.key' '' ''
detect 'OpenLiteSpeed' 'openlitespeed' '/usr/local/lsws/bin/openlitespeed' 'openlitespeed' 'openlitespeed'
detect 'Caddy' 'caddy' '/etc/caddy/Caddyfile' 'caddy' 'caddy'
detect 'HAProxy' 'haproxy' '/etc/haproxy/haproxy.cfg' 'haproxy' 'haproxy'
detect 'Traefik' 'traefik' '/etc/traefik/traefik.yml /etc/traefik/traefik.yaml /etc/traefik/traefik.toml' 'traefik' 'traefik'
detect 'Envoy' 'envoy' '/etc/envoy/envoy.yaml' 'envoy' 'envoy'
detect 'OpenResty' 'openresty' '/usr/local/openresty/bin/openresty' 'openresty' 'openresty'
detect 'Tengine' '' '/usr/local/tengine/sbin/nginx' 'tengine' 'tengine'
detect 'Lighttpd' 'lighttpd' '/etc/lighttpd/lighttpd.conf' 'lighttpd' 'lighttpd'
detect 'Apache Tomcat' 'catalina.sh' '/etc/tomcat*/server.xml /opt/tomcat/bin/catalina.sh' 'tomcat tomcat[0-9] tomcat[0-9][0-9]' 'tomcat tomcat9 tomcat10 tomcat11'
detect 'PHP CLI' 'php' '/opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php /usr/local/php*/bin/php /www/server/php/*/bin/php /opt/plesk/php/*/bin/php' 'php-cli php[0-9]*-cli ea-php*-php-cli alt-php*-cli' ''
detect 'PHP-FPM' 'php-fpm' '/etc/php/*/fpm/php-fpm.conf /etc/php-fpm.conf /opt/plesk/php/*/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /www/server/php/*/sbin/php-fpm' 'php-fpm php[0-9]*-fpm ea-php*-php-fpm alt-php*-fpm' 'php-fpm php5.6-fpm php7.0-fpm php7.1-fpm php7.2-fpm php7.3-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm php-fpm5.6 php-fpm7.0 php-fpm7.1 php-fpm7.2 php-fpm7.3 php-fpm7.4 php-fpm8.0 php-fpm8.1 php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5'
detect 'LiteSpeed PHP (LSAPI)' 'lsphp' '/usr/local/lsws/lsphp*/bin/lsphp /opt/alt/php*/usr/bin/lsphp' 'lsphp[0-9][0-9] lsphp' 'lsphp'
detect 'Node.js' 'node nodejs' '' 'nodejs' 'node nodejs'
detect 'Python' 'python3 python' '' 'python3' ''
detect 'Gunicorn' 'gunicorn' '/etc/gunicorn.d' 'gunicorn gunicorn3' 'gunicorn'
detect 'uWSGI' 'uwsgi' '/etc/uwsgi' 'uwsgi' 'uwsgi'
detect 'Uvicorn' 'uvicorn' '' 'python3-uvicorn' 'uvicorn'
detect 'Java' 'java' '' '' 'java'
detect 'Ruby' 'ruby' '' 'ruby' ''
detect 'Passenger' 'passenger-status' '' 'passenger ea-apache24-mod-passenger' ''
detect 'Composer' 'composer' '' 'composer' ''
detect 'WP-CLI' 'wp' '' 'wp-cli' ''

sig_group 'Data stores'
detect 'Redis server' 'redis-server' '/etc/redis/redis.conf /etc/redis.conf /www/server/redis/src/redis-server' 'redis redis-server' 'redis redis-server'
detect 'Valkey server' 'valkey-server' '/etc/valkey/valkey.conf /etc/valkey.conf' 'valkey valkey-server' 'valkey valkey-server'
detect 'KeyDB server' 'keydb-server' '/etc/keydb/keydb.conf' 'keydb keydb-server' 'keydb keydb-server'
detect 'Memcached' 'memcached' '/etc/memcached.conf /etc/sysconfig/memcached' 'memcached' 'memcached'
detect 'Varnish Cache' 'varnishd' '/etc/varnish/default.vcl' 'varnish' 'varnish varnishd'
detect 'PHP OPcache (module files or package)' '' '/etc/php/*/mods-available/opcache.ini /usr/lib/php/*/opcache.so /opt/cpanel/ea-php*/root/usr/lib64/php/modules/opcache.so' 'php-opcache php[0-9]*-opcache ea-php*-php-opcache' ''
detect 'PHP APCu (module files or package)' '' '/etc/php/*/mods-available/apcu.ini /usr/lib/php/*/apcu.so' 'php-apcu php[0-9]*-apcu' ''
detect 'MariaDB server' 'mariadbd' '/etc/mysql/mariadb.conf.d/50-server.cnf /www/server/mysql/bin/mariadbd' 'mariadb-server MariaDB-server mariadb' 'mariadb mariadbd'
detect 'Oracle MySQL server (package)' '' '' 'mysql-community-server mysql-server-core-* mysql-community-server-core' ''
detect 'Percona Server for MySQL (package)' '' '' 'percona-server-server percona-server-server-* Percona-Server-server-*' ''
detect 'MySQL-compatible server family' 'mysqld mariadbd' '/www/server/mysql/bin/mysqld' 'mysql-server mysql-community-server mariadb-server MariaDB-server percona-server-server' 'mysqld mysql mariadb mariadbd'
detect 'PostgreSQL server' 'postgres' '/etc/postgresql/*/*/postgresql.conf /usr/lib/postgresql/*/bin/postgres /usr/pgsql-*/bin/postgres' 'postgresql postgresql-[0-9] postgresql-[0-9][0-9] postgresql-server postgresql[0-9]*-server' 'postgres postgresql'
detect 'MongoDB server' 'mongod' '/etc/mongod.conf' 'mongodb-org-server mongodb-server mongodb-server-core mongodb-enterprise-server' 'mongod mongodb'
detect 'SQLite CLI' 'sqlite3' '' 'sqlite sqlite3' ''
detect 'Elasticsearch' 'elasticsearch' '/etc/elasticsearch/elasticsearch.yml /usr/share/elasticsearch/bin/elasticsearch' 'elasticsearch' 'elasticsearch'
detect 'OpenSearch' 'opensearch' '/etc/opensearch/opensearch.yml /usr/share/opensearch/bin/opensearch' 'opensearch' 'opensearch'
detect 'RabbitMQ' 'rabbitmq-server' '/etc/rabbitmq/rabbitmq.conf' 'rabbitmq-server' 'rabbitmq-server'

sig_group 'Security'
detect 'ConfigServer Firewall (CSF/LFD)' 'csf lfd' '/etc/csf/csf.conf /usr/local/csf/bin/csf /usr/sbin/csf /usr/sbin/lfd' 'csf' 'csf lfd'
detect 'Imunify360 WebShield / firewall' '' '' 'imunify360-firewall imunify360-webshield' 'imunify360-webshield'
detect 'ImunifyAV' 'imunify-antivirus' '/var/imunify360/imunify-antivirus.te' 'imunify-antivirus' 'imunify-antivirus'
detect 'Imunify shared agent' 'imunify360-agent' '/etc/sysconfig/imunify360/imunify360.config' 'imunify360-agent' 'imunify360'
detect 'CloudLinux tools and release' 'cldetect' '/etc/cloudlinux-release' 'cloudlinux-release lve-utils' ''
detect 'CloudLinux LVE Manager' '' '' 'lvemanager' ''
detect 'CloudLinux CageFS' 'cagefsctl' '/etc/cagefs' 'cagefs' ''
detect 'CloudLinux MySQL Governor' 'dbctl' '/etc/container/mysql-governor.xml' 'governor-mysql' 'db_governor'
detect 'Fail2ban' 'fail2ban-client' '/etc/fail2ban/jail.conf' 'fail2ban' 'fail2ban fail2ban-server'
detect 'CrowdSec' 'crowdsec cscli' '/etc/crowdsec/config.yaml' 'crowdsec' 'crowdsec'
detect 'CrowdSec firewall bouncer' 'crowdsec-firewall-bouncer' '/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml' 'crowdsec-firewall-bouncer*' 'crowdsec-firewall-bouncer'
detect 'SSHGuard' 'sshguard' '/etc/sshguard/sshguard.conf /etc/sshguard.conf' 'sshguard' 'sshguard'
detect 'firewalld' 'firewall-cmd firewalld' '/etc/firewalld/firewalld.conf' 'firewalld' 'firewalld'
detect 'UFW' 'ufw' '/etc/ufw/ufw.conf' 'ufw' 'ufw'
detect 'nftables tooling' 'nft' '/etc/nftables.conf' 'nftables' 'nftables'
detect 'iptables tooling' 'iptables ip6tables' '' 'iptables iptables-nft iptables-legacy' ''
detect 'ipset tooling' 'ipset' '' 'ipset' ''
detect 'ModSecurity engine files' '' '/usr/lib/apache2/modules/mod_security2.so /usr/lib64/httpd/modules/mod_security2.so /usr/lib/nginx/modules/ngx_http_modsecurity_module.so /etc/modsecurity/modsecurity.conf' 'libapache2-mod-security2 libmodsecurity3 libnginx-mod-http-modsecurity mod_security ea-apache24-mod_security2' ''
detect 'OWASP ModSecurity CRS ruleset' '' '/usr/share/modsecurity-crs/rules /etc/modsecurity/crs' 'modsecurity-crs mod_security_crs' ''
detect 'ClamAV' 'clamscan clamd freshclam' '/etc/clamav/clamd.conf /etc/clamd.d/scan.conf' 'clamav clamav-daemon clamd' 'clamav-daemon clamd clamd@scan clamav-freshclam freshclam'
detect 'Linux Malware Detect' 'maldet' '/usr/local/maldetect/maldet' 'maldetect' ''
detect 'Wazuh agent' '' '/var/ossec/bin/wazuh-agentd' 'wazuh-agent' 'wazuh-agent wazuh-agentd'
detect 'Wazuh manager' '' '/var/ossec/bin/wazuh-analysisd' 'wazuh-manager' 'wazuh-manager wazuh-analysisd'
detect 'OSSEC' '' '/var/ossec/bin/ossec-control' 'ossec-hids ossec-hids-agent ossec-hids-server' 'ossec ossec-agentd ossec-analysisd'
detect 'Suricata' 'suricata' '/etc/suricata/suricata.yaml' 'suricata' 'suricata'
detect 'Audit daemon' 'auditctl auditd' '/etc/audit/auditd.conf' 'audit auditd' 'auditd'
detect 'AppArmor tooling' 'aa-status apparmor_status' '/etc/apparmor/parser.conf' 'apparmor' 'apparmor'
detect 'SELinux tooling or config' 'getenforce sestatus' '/etc/selinux/config' 'policycoreutils libselinux-utils' ''
detect 'Lynis' 'lynis' '' 'lynis' ''
detect 'Certbot' 'certbot' '/snap/bin/certbot' 'certbot' 'certbot'
detect 'acme.sh' 'acme.sh' '/root/.acme.sh/acme.sh' '' ''
detect 'acme-client / dehydrated' 'acme-client dehydrated' '/etc/dehydrated/config' 'acme-client dehydrated' ''
detect 'lego ACME client' 'lego' '' 'lego' ''

sig_group 'Mail, DNS, FTP'
detect 'Postfix' 'postfix postconf' '/etc/postfix/main.cf' 'postfix' 'postfix'
detect 'Exim' 'exim exim4' '/etc/exim.conf /etc/exim4/exim4.conf.template' 'exim exim4-base' 'exim exim4'
detect 'Sendmail MTA' '' '/etc/mail/sendmail.cf' 'sendmail sendmail-bin' 'sendmail'
detect 'OpenSMTPD' 'smtpctl' '/etc/smtpd.conf /etc/opensmtpd/smtpd.conf' 'opensmtpd' 'smtpd opensmtpd'
detect 'Dovecot' 'dovecot' '/etc/dovecot/dovecot.conf' 'dovecot dovecot-core' 'dovecot'
detect 'Rspamd' 'rspamd rspamadm' '/etc/rspamd/rspamd.conf' 'rspamd' 'rspamd'
detect 'SpamAssassin' 'spamassassin spamd' '/etc/spamassassin/local.cf /etc/mail/spamassassin/local.cf' 'spamassassin spamd' 'spamassassin spamd'
detect 'Amavis' 'amavisd amavisd-new' '/etc/amavis/conf.d /etc/amavisd/amavisd.conf' 'amavis amavisd-new' 'amavis amavisd amavisd-new'
detect 'OpenDKIM' 'opendkim' '/etc/opendkim.conf' 'opendkim' 'opendkim'
detect 'BIND DNS server' 'named' '/etc/named.conf /etc/bind/named.conf' 'bind bind9' 'named bind9'
detect 'PowerDNS authoritative' 'pdns_server' '/etc/pdns/pdns.conf /etc/powerdns/pdns.conf' 'pdns pdns-server' 'pdns pdns_server'
detect 'PowerDNS Recursor' 'pdns_recursor' '/etc/pdns/recursor.conf /etc/powerdns/recursor.conf' 'pdns-recursor' 'pdns-recursor pdns_recursor'
detect 'Unbound' 'unbound' '/etc/unbound/unbound.conf' 'unbound' 'unbound'
detect 'dnsmasq' 'dnsmasq' '/etc/dnsmasq.conf' 'dnsmasq dnsmasq-base' 'dnsmasq'
detect 'Knot DNS' 'knotd' '/etc/knot/knot.conf' 'knot' 'knot knotd'
detect 'CoreDNS' 'coredns' '/etc/coredns/Corefile' 'coredns' 'coredns'
detect 'NSD' 'nsd' '/etc/nsd/nsd.conf' 'nsd' 'nsd'
detect 'OpenSSH server' 'sshd' '/etc/ssh/sshd_config' 'openssh-server openssh' 'ssh sshd'
detect 'ProFTPD' 'proftpd' '/etc/proftpd/proftpd.conf /etc/proftpd.conf' 'proftpd proftpd-core' 'proftpd'
detect 'Pure-FTPd' 'pure-ftpd' '/etc/pure-ftpd/pure-ftpd.conf /etc/pure-ftpd.conf' 'pure-ftpd pure-ftpd-common' 'pure-ftpd'
detect 'vsftpd' 'vsftpd' '/etc/vsftpd.conf /etc/vsftpd/vsftpd.conf' 'vsftpd' 'vsftpd'

sig_group 'Containers and tunnels'
detect 'Docker Engine' 'dockerd' '/etc/docker/daemon.json /run/docker.sock' 'docker-ce docker.io moby-engine docker' 'docker dockerd'
detect 'Docker-compatible CLI' 'docker' '' 'docker-ce-cli docker-cli moby-cli podman-docker' ''
detect 'Docker Compose standalone' 'docker-compose' '/usr/libexec/docker/cli-plugins/docker-compose /usr/lib/docker/cli-plugins/docker-compose' 'docker-compose docker-compose-plugin docker-compose-v2' ''
detect 'Podman' 'podman' '/run/podman/podman.sock' 'podman' 'podman'
detect 'containerd' 'containerd' '/etc/containerd/config.toml' 'containerd containerd.io' 'containerd'
detect 'CRI-O' 'crio' '/etc/crio/crio.conf' 'cri-o' 'crio'
detect 'Kubernetes node' 'kubelet' '/var/lib/kubelet/config.yaml' 'kubelet' 'kubelet'
detect 'Kubernetes CLI' 'kubectl' '' 'kubectl' ''
detect 'K3s' 'k3s' '/etc/rancher/k3s/config.yaml /var/lib/rancher/k3s' '' 'k3s k3s-agent'
detect 'MicroK8s' 'microk8s' '/snap/bin/microk8s' '' ''
detect 'LXD' 'lxd' '/var/snap/lxd/common/lxd/unix.socket' 'lxd' 'lxd'
detect 'Incus' 'incusd' '/run/incus/unix.socket /var/lib/incus/unix.socket' 'incus' 'incus incusd'
detect 'Proxmox VE' 'pveversion' '/usr/bin/pveversion /etc/pve/.version' 'pve-manager' 'pveproxy pvedaemon'
detect 'libvirt' 'libvirtd virtqemud' '/etc/libvirt/libvirtd.conf' 'libvirt-daemon libvirt' 'libvirtd virtqemud'
detect 'Cloudflare Tunnel agent' 'cloudflared' '/etc/cloudflared/config.yml /etc/cloudflared/config.yaml' 'cloudflared' 'cloudflared'
detect 'Tailscale' 'tailscaled' '/var/lib/tailscale' 'tailscale' 'tailscaled'
detect 'WireGuard tools' 'wg wg-quick' '' 'wireguard-tools' ''
detect 'OpenVPN' 'openvpn' '/etc/openvpn/server/*.conf' 'openvpn' 'openvpn'
detect 'ZeroTier' 'zerotier-one' '/var/lib/zerotier-one' 'zerotier-one' 'zerotier-one'

sig_group 'Jobs and monitoring'
detect 'JetBackup' 'jetbackup5' '/usr/local/jetapps/usr/bin/jetbackup5 /usr/local/jetapps/usr/bin/jetbackup5api' 'jetbackup5 jetbackup' 'jetbackup5d'
detect 'Acronis backup agent' '' '/usr/lib/Acronis/BackupAndRecovery/mms /opt/Acronis/BackupAndRecovery' 'acronis-backup*' 'acronis_mms'
detect 'Restic' 'restic' '' 'restic' ''
detect 'BorgBackup' 'borg' '' 'borgbackup' ''
detect 'Duplicity' 'duplicity' '' 'duplicity' ''
detect 'rclone' 'rclone' '' 'rclone' 'rclone'
detect 'rsync' 'rsync' '/etc/rsyncd.conf' 'rsync' 'rsync rsyncd'
detect 'Cron daemon' 'cron crond' '/etc/crontab' 'cron cronie dcron' 'cron crond'
detect 'systemd timer tooling' 'systemd-run' '' '' ''
detect 'Supervisor' 'supervisord supervisorctl' '/etc/supervisord.conf /etc/supervisor/supervisord.conf' 'supervisor' 'supervisor supervisord'
detect 'Monit' 'monit' '/etc/monitrc /etc/monit/monitrc' 'monit' 'monit'
detect 'PM2' 'pm2' '' '' ''
detect 'Prometheus' 'prometheus' '/etc/prometheus/prometheus.yml' 'prometheus' 'prometheus'
detect 'Prometheus node exporter' 'node_exporter prometheus-node-exporter' '' 'prometheus-node-exporter' 'node_exporter prometheus-node-exporter'
detect 'Grafana' 'grafana grafana-server' '/etc/grafana/grafana.ini' 'grafana grafana-enterprise' 'grafana grafana-server'
detect 'Netdata' 'netdata' '/etc/netdata/netdata.conf' 'netdata' 'netdata'
detect 'Zabbix agent' 'zabbix_agentd zabbix_agent2' '/etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agent2.conf' 'zabbix-agent zabbix-agent2' 'zabbix-agent zabbix-agent2 zabbix_agentd zabbix_agent2'
detect 'Datadog agent' 'datadog-agent' '/etc/datadog-agent/datadog.yaml' 'datadog-agent' 'datadog-agent'
detect 'Telegraf' 'telegraf' '/etc/telegraf/telegraf.conf' 'telegraf' 'telegraf'
detect 'New Relic infrastructure agent' 'newrelic-infra' '/etc/newrelic-infra.yml' 'newrelic-infra' 'newrelic-infra'
detect 'Elastic Agent' 'elastic-agent' '/opt/Elastic/Agent/elastic-agent' 'elastic-agent' 'elastic-agent'
detect 'Fluent Bit' 'fluent-bit' '/etc/fluent-bit/fluent-bit.conf' 'fluent-bit' 'fluent-bit'
detect 'Vector log agent' 'vector' '/etc/vector/vector.yaml /etc/vector/vector.toml' 'vector' 'vector'
detect 'rsyslog' 'rsyslogd' '/etc/rsyslog.conf' 'rsyslog' 'rsyslog rsyslogd'
detect 'syslog-ng' 'syslog-ng' '/etc/syslog-ng/syslog-ng.conf' 'syslog-ng syslog-ng-core' 'syslog-ng'

sig_group 'Platforms and DevOps'
detect 'K0s' 'k0s' '/var/lib/k0s' '' 'k0scontroller k0sworker'
detect 'RKE2' 'rke2' '/etc/rancher/rke2 /var/lib/rancher/rke2' 'rke2-server rke2-agent' 'rke2-server rke2-agent'
detect 'OpenShift' 'oc openshift-install' '/etc/origin' 'openshift-clients' ''
detect 'etcd' 'etcd' '/etc/etcd/etcd.conf' 'etcd' 'etcd'
detect 'Helm' 'helm' '' 'helm' ''
detect 'Rancher' '' '/var/lib/rancher/management-state' '' 'rancher-system-agent'
detect 'HashiCorp Nomad' 'nomad' '/etc/nomad.d' 'nomad' 'nomad'
detect 'HashiCorp Consul' 'consul' '/etc/consul.d' 'consul' 'consul'
detect 'HashiCorp Vault' 'vault' '/etc/vault.d' 'vault' 'vault'
detect 'Portainer' '' '/var/lib/portainer' '' 'portainer'
detect 'Coolify' '' '/data/coolify' '' ''
detect 'CapRover' '' '/captain/data' '' ''
detect 'GitLab' 'gitlab-ctl' '/etc/gitlab/gitlab.rb' 'gitlab-ce gitlab-ee' 'gitlab-runsvdir'
detect 'GitLab Runner' 'gitlab-runner' '/etc/gitlab-runner/config.toml' 'gitlab-runner' 'gitlab-runner'
detect 'Jenkins' '' '/var/lib/jenkins /etc/default/jenkins' 'jenkins' 'jenkins'
detect 'Gitea or Forgejo' 'gitea forgejo' '/etc/gitea/app.ini /etc/forgejo/app.ini' 'gitea forgejo' 'gitea forgejo'
detect 'GitHub Actions runner' '' '/opt/actions-runner /home/*/actions-runner' '' 'Runner.Listener'
detect 'Harbor registry' '' '/data/harbor' '' ''
detect 'Nextcloud' '' '/var/www/nextcloud/occ /var/www/html/occ' 'nextcloud' ''
detect 'Apache Kafka' 'kafka-server-start.sh kafka-topics' '/opt/kafka/bin/kafka-server-start.sh /etc/kafka' 'kafka confluent-kafka' 'kafka'
detect 'Apache ZooKeeper' 'zkServer.sh' '/etc/zookeeper /opt/zookeeper/bin/zkServer.sh' 'zookeeper zookeeperd' 'zookeeper'
detect 'Apache Cassandra' 'cassandra' '/etc/cassandra/cassandra.yaml' 'cassandra' 'cassandra'
detect 'ClickHouse' 'clickhouse-server clickhouse' '/etc/clickhouse-server/config.xml' 'clickhouse-server' 'clickhouse-server clickhouse-serv'
detect 'InfluxDB' 'influxd' '/etc/influxdb/config.toml /etc/influxdb/influxdb.conf' 'influxdb influxdb2' 'influxd influxdb'
detect 'TimescaleDB' '' '' 'timescaledb-*' ''
detect 'MinIO object storage' 'minio' '/etc/default/minio' 'minio' 'minio'
detect 'Ceph storage' 'ceph' '/etc/ceph/ceph.conf' 'ceph ceph-common' 'ceph-mon ceph-osd ceph-mgr ceph-mds'
detect 'GlusterFS' 'glusterd' '/etc/glusterfs/glusterd.vol' 'glusterfs-server' 'glusterd'
detect 'NFS server' 'exportfs' '/etc/exports' 'nfs-kernel-server nfs-utils' 'nfsd nfs-server'
detect 'Samba' 'smbd' '/etc/samba/smb.conf' 'samba' 'smbd smb'
detect 'Keepalived' 'keepalived' '/etc/keepalived/keepalived.conf' 'keepalived' 'keepalived'
detect 'Pacemaker cluster' 'pcs crm_mon' '/etc/corosync/corosync.conf' 'pacemaker' 'pacemakerd corosync'
detect 'Squid proxy' 'squid' '/etc/squid/squid.conf' 'squid' 'squid'
detect 'Oracle Database' '' '/etc/oratab' '' 'tnslsnr'
detect 'Microsoft SQL Server' '' '/opt/mssql/bin/sqlservr' 'mssql-server' 'sqlservr mssql-server'
detect 'Zimbra' '' '/opt/zimbra/bin/zmcontrol' '' ''
detect 'Asterisk' 'asterisk' '/etc/asterisk/asterisk.conf' 'asterisk' 'asterisk'
detect 'FreeSWITCH' 'freeswitch' '/etc/freeswitch/freeswitch.xml' 'freeswitch' 'freeswitch'
detect 'NATS' 'nats-server' '' 'nats-server' 'nats-server'
detect 'Ollama' 'ollama' '/usr/share/ollama' '' 'ollama'
detect 'NVIDIA GPU driver' 'nvidia-smi' '/proc/driver/nvidia/version' '' 'nvidia-persistenced'
detect 'Veeam agent' 'veeamconfig' '/etc/veeam' 'veeam' 'veeamservice'
detect 'Bacula' 'bconsole' '/etc/bacula/bacula-dir.conf' 'bacula-client bacula-common' 'bacula-fd bacula-dir'
detect 'Proxmox Backup' 'proxmox-backup-client' '/etc/proxmox-backup' 'proxmox-backup-server' 'proxmox-backup'
detect 'Uptime Kuma' '' '/opt/uptime-kuma' '' ''
detect 'Glances' 'glances' '/etc/glances/glances.conf' 'glances' 'glances'
detect 'Nagios' '' '/etc/nagios/nagios.cfg /usr/local/nagios/bin/nagios' 'nagios nagios4 nagios-nrpe-server' 'nagios nagios4 nrpe'

sig_group 'Messaging, search and more'
detect 'Apache ActiveMQ' 'activemq' '/etc/activemq /opt/activemq/bin/activemq' 'activemq' 'activemq'
detect 'NSQ' 'nsqd' '' 'nsq' 'nsqd'
detect 'Mosquitto MQTT' 'mosquitto' '/etc/mosquitto/mosquitto.conf' 'mosquitto' 'mosquitto'
detect 'EMQX' 'emqx' '/etc/emqx/emqx.conf' 'emqx' 'emqx'
detect 'Apache Solr' 'solr' '/opt/solr/bin/solr /etc/default/solr.in.sh' 'solr' 'solr'
detect 'Meilisearch' 'meilisearch' '' 'meilisearch' 'meilisearch'
detect 'Typesense' 'typesense-server' '/etc/typesense/typesense-server.ini' 'typesense-server' 'typesense-server'
detect 'Logstash' 'logstash' '/etc/logstash/logstash.yml /usr/share/logstash/bin/logstash' 'logstash' 'logstash'
detect 'Kibana' 'kibana' '/etc/kibana/kibana.yml /usr/share/kibana/bin/kibana' 'kibana' 'kibana'
detect 'OpenSearch Dashboards' '' '/etc/opensearch-dashboards/opensearch_dashboards.yml' 'opensearch-dashboards' 'opensearch-dashboards'
detect 'Filebeat' 'filebeat' '/etc/filebeat/filebeat.yml' 'filebeat' 'filebeat'
detect 'Metricbeat' 'metricbeat' '/etc/metricbeat/metricbeat.yml' 'metricbeat' 'metricbeat'
detect 'Grafana Loki' 'loki' '/etc/loki/config.yml /etc/loki/loki.yaml' 'loki' 'loki'
detect 'Promtail' 'promtail' '/etc/promtail/config.yml' 'promtail' 'promtail'
detect 'Prometheus Alertmanager' 'alertmanager' '/etc/alertmanager/alertmanager.yml' 'prometheus-alertmanager alertmanager' 'alertmanager prometheus-alertmanager'
detect 'VictoriaMetrics' 'victoria-metrics' '' 'victoria-metrics' 'victoria-metrics victoriametrics'
detect 'Jaeger' 'jaeger-all-in-one' '' '' 'jaeger jaeger-all-in-one'
detect 'PgBouncer' 'pgbouncer' '/etc/pgbouncer/pgbouncer.ini' 'pgbouncer' 'pgbouncer'
detect 'Pgpool-II' 'pgpool' '/etc/pgpool2/pgpool.conf /etc/pgpool-II/pgpool.conf' 'pgpool2 pgpool-II' 'pgpool pgpool2 pgpool-II'
detect 'Patroni' 'patroni' '/etc/patroni/config.yml /etc/patroni.yml' 'patroni' 'patroni'
detect 'ProxySQL' 'proxysql' '/etc/proxysql.cnf' 'proxysql' 'proxysql'
detect 'MariaDB MaxScale' 'maxscale' '/etc/maxscale.cnf' 'maxscale' 'maxscale'
detect 'CouchDB' 'couchdb' '/opt/couchdb/etc/local.ini /etc/couchdb/local.ini' 'couchdb' 'couchdb'
detect 'Couchbase Server' '' '/opt/couchbase/bin/couchbase-server' 'couchbase-server couchbase-server-community' 'couchbase-server memcached.couch'
detect 'CockroachDB' 'cockroach' '' '' 'cockroach cockroachdb'
detect 'ScyllaDB' 'scylla' '/etc/scylla/scylla.yaml' 'scylla scylla-server' 'scylla scylla-server'
detect 'Neo4j' 'neo4j' '/etc/neo4j/neo4j.conf' 'neo4j' 'neo4j'
detect 'Dragonfly' 'dragonfly' '/etc/dragonfly/dragonfly.conf' 'dragonfly' 'dragonfly'
detect 'Qdrant' 'qdrant' '/etc/qdrant' 'qdrant' 'qdrant'
detect 'Nginx Unit' 'unitd' '' 'unit' 'unit unitd'
detect 'FrankenPHP' 'frankenphp' '' 'frankenphp' 'frankenphp'
detect 'Apache Traffic Server' 'traffic_server' '/etc/trafficserver/records.config /etc/trafficserver/records.yaml' 'trafficserver' 'trafficserver traffic_server'
detect 'Pound' 'pound' '/etc/pound.cfg /etc/pound/pound.cfg' 'pound' 'pound'
detect 'stunnel' 'stunnel stunnel4' '/etc/stunnel/stunnel.conf' 'stunnel4 stunnel' 'stunnel stunnel4'
detect 'WildFly or JBoss' '' '/opt/wildfly/bin/standalone.sh /opt/jboss/bin/standalone.sh' 'wildfly' 'wildfly jboss'
detect 'Jetty' '' '/etc/jetty/jetty.conf /opt/jetty/start.jar' 'jetty9 jetty' 'jetty jetty9'
detect 'Celery' 'celery' '' 'python3-celery' 'celery'
detect 'Sidekiq' 'sidekiq' '' '' 'sidekiq'
detect 'Puma' 'puma' '' 'puma' 'puma'
detect 'dotnet runtime' 'dotnet' '' 'dotnet-runtime-* aspnetcore-runtime-*' 'dotnet'
detect 'Deno' 'deno' '' '' 'deno'
detect 'Bun' 'bun' '' '' 'bun'
detect 'SonarQube' '' '/opt/sonarqube/bin' '' 'sonarqube'
detect 'Nexus Repository' '' '/opt/nexus/bin/nexus /opt/sonatype/nexus/bin/nexus' '' 'nexus'
detect 'JFrog Artifactory' '' '/opt/jfrog/artifactory' 'jfrog-artifactory-oss' 'artifactory'
detect 'Pi-hole' 'pihole' '/etc/pihole' '' 'pihole-FTL'
detect 'AdGuard Home' 'AdGuardHome' '/opt/AdGuardHome/AdGuardHome' '' 'AdGuardHome'
detect 'dnsdist' 'dnsdist' '/etc/dnsdist/dnsdist.conf' 'dnsdist' 'dnsdist'
detect 'FRRouting' 'vtysh' '/etc/frr/frr.conf' 'frr' 'frr zebra bgpd'
detect 'BIRD routing' 'bird birdc' '/etc/bird/bird.conf /etc/bird.conf' 'bird bird2' 'bird bird6'
detect 'LVS load balancer tools' 'ipvsadm' '/etc/ipvsadm.rules' 'ipvsadm' ''
detect 'DRBD' 'drbdadm' '/etc/drbd.conf' 'drbd-utils' 'drbd'
detect 'Mailman' 'mailman' '/etc/mailman3/mailman.cfg /etc/mailman.cfg' 'mailman3 mailman' 'mailman3 mailman'
detect 'Roundcube' '' '/etc/roundcube/config.inc.php /usr/share/roundcube/index.php' 'roundcube-core roundcube' ''
detect 'Cyrus IMAP' 'cyrmaster' '/etc/imapd.conf' 'cyrus-imapd' 'cyrus-imapd cyrmaster'
detect 'Icinga' 'icinga2' '/etc/icinga2/icinga2.conf' 'icinga2' 'icinga2'
detect 'Graylog' '' '/etc/graylog/server/server.conf' 'graylog-server' 'graylog-server'
}

print_signatures() {
    local show_missing=${1:-no} group label status text
    title 'Recognized software' \
        'RUNNING = process or running unit. PRESENT = installed. TRACE = leftover path or unit.'
    while IFS= read -r group; do
        [[ -n $group ]] || continue
        section "$group"
        while IFS='|' read -r _ label status text; do
            [[ $show_missing == yes || $status != NOT-DETECTED ]] || continue
            printf '%-32s %-13s%s\n' "$label" "$status" "$text"
        done <<< "$(grep -F "$group|" <<< "$sig_rows")"
    done <<< "$sig_groups"
}

run_audit() {
    local show_missing=yes inventory=no journal=no all_services=no unit ignored raw
    while (($#)); do
        case $1 in
            --found-only) show_missing=no ;;
            --inventory) inventory=yes ;;
            --journal) journal=yes ;;
            --all-services) all_services=yes ;;
            *) printf 'Unknown argument: %s\n' "$1" >&2; return 2 ;;
        esac
        shift
    done
    section 'Linux Host Audit'
    host_report
    [[ -n ${sig_rows:-} ]] || scan_evidence
    print_signatures "$show_missing"

    if [[ $all_services == yes && $systemd_visible == yes ]]; then
        while read -r unit ignored; do
            [[ $unit == *.service && $unit != *@.service ]] || continue
            if [[ $diagnostic_units != *$'\n'"$unit"$'\n'* ]]; then
                diagnostic_units+="$unit"$'\n'
            fi
        done <<< "$units$active_units"
    fi
    service_report
    service_extra

    section 'Cache configuration evidence'
    printf '%s\n' 'Configuration matches may be inactive, overridden, or outside the loaded include tree.' \
        'A running cache service alone does not show that a site uses it.'
    if has awk; then
        cache_directives 'NGINX FastCGI cache' '^[ \t]*fastcgi_cache[ \t]+[^ \t#;]+[ \t]*;' '^[ \t]*[a-z_]+[ \t]+off[ \t]*;' \
            /etc/nginx/nginx.conf /etc/nginx/{conf.d,sites-enabled,vhosts.d}/* \
            /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/{conf.d,vhost}/* \
            /www/server/panel/vhost/nginx/*.conf
        cache_directives 'NGINX proxy cache' '^[ \t]*proxy_cache[ \t]+[^ \t#;]+[ \t]*;' '^[ \t]*[a-z_]+[ \t]+off[ \t]*;' \
            /etc/nginx/nginx.conf /etc/nginx/{conf.d,sites-enabled,vhosts.d}/* \
            /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/{conf.d,vhost}/* \
            /www/server/panel/vhost/nginx/*.conf
        cache_directives 'Apache mod_cache' '^[ \t]*cacheenable[ \t]+(disk|socache|fd)[ \t]' '' \
            /etc/apache2/apache2.conf /etc/apache2/{conf-enabled,mods-enabled,sites-enabled}/* \
            /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf /usr/local/apache/conf/httpd.conf \
            /etc/apache2/conf/httpd.conf /www/server/panel/vhost/apache/*.conf
        cache_directives 'LiteSpeed cache rules' '^[ \t]*(cacheengine[ \t]+on([ \t#]|$)|enablecache[ \t]+1([ \t#]|$)|<enablecache>[ \t]*1[ \t]*</enablecache>)' '' \
            /usr/local/lsws/conf/httpd_config.{conf,xml} /usr/local/lsws/conf/vhosts/*/*.conf
        cache_directives 'PHP OPcache extension' '^[ \t]*zend_extension[ \t]*=[ \t]*[^;#]*opcache' '' \
            /etc/php.ini /etc/php.d/*opcache*.ini /etc/php*/conf.d/*opcache*.ini \
            /etc/php/*/*/php.ini /etc/php/*/*/conf.d/*opcache*.ini \
            /opt/cpanel/ea-php*/root/etc/php.d/*opcache*.ini /opt/plesk/php/*/etc/php.d/*opcache*.ini \
            /www/server/php/*/etc/php.ini
    else
        printf 'Configuration checks unavailable (awk missing)\n'
    fi

    section 'WordPress cache drop-ins in common web roots'
    local root dropin wordpress_roots=0
    for root in /var/www/html /var/www/*/public /home/*/public_html \
        /home/*/domains/*/public_html /var/www/vhosts/*/httpdocs /www/wwwroot/*; do
        [[ -f $root/wp-includes/version.php ]] || continue
        ((wordpress_roots+=1))
        for dropin in advanced-cache.php object-cache.php; do
            if [[ -f $root/wp-content/$dropin ]]; then
                printf 'TRACE  %q\n' "$root/wp-content/$dropin"
            fi
        done
    done
    printf 'WordPress roots visible at checked locations: %s\n' "$wordpress_roots"

    if [[ $inventory == yes ]]; then
        section 'Installed package and profile records'
        printf '%s\n' "${packages:-Unavailable or empty}"
        section 'Service definitions and runtime states'
        printf '%s\n' "$units" "$active_units"
        section 'Local TCP and UDP listeners (addresses and ports)'
        raw=$(net_listeners | awk '{ print $1, $3 ":" $2 }' | sort -u)
        printf '%s\n' "${raw:-Listener inventory unavailable}"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Shared report helpers
# ---------------------------------------------------------------------------
ui_colors() {
    c_red='' c_yel='' c_grn='' c_dim='' c_bold='' c_cyan='' c_off=''
    if [[ ! ${NO_COLOR+x} ]] && [[ ${LHA_COLOR:-} == always || -t 1 ]]; then
        c_red=$'\033[91m' c_yel=$'\033[93m' c_grn=$'\033[92m' c_dim=$'\033[90m'
        c_bold=$'\033[1m' c_cyan=$'\033[96m' c_off=$'\033[0m'
    fi
    if [[ -z ${glyph_mode:-} ]]; then
        glyph_mode=ascii
        if [[ -t 1 && ${LHA_LOCALE:-} == *[Uu][Tt][Ff]* ]]; then glyph_mode=utf8; fi
    fi
    glyph_set
}

# Container, log and event text is attacker-influenced: strip terminal control bytes.
# U+0080 to U+009F include an 8-bit CSI, and take two bytes in UTF-8.
LHA_C1=$'\xc2[\x80-\x9f]'
clean() { tr -d '\000-\010\013-\037\177' | LC_ALL=C sed "s/$LHA_C1//g"; }

# Every external probe that can hang goes through this, with stdin closed.
run_t() {
    local limit=$1
    shift
    if has timeout; then timeout "$limit" "$@" </dev/null; else "$@" </dev/null; fi
}

title() {
    local rule=$((72 - ${#1}))
    if [[ $glyph_mode == utf8 ]]; then
        ((rule > 0)) || rule=1
        printf -v rule '%*s' "$rule" ''
        printf '\n%s%s%s %s %s%s%s\n' "$c_dim" "$g_h$g_h" "$c_off$c_bold$c_cyan" "$1" "$c_off$c_dim" "${rule// /$g_h}" "$c_off"
    else
        printf '\n%s== %s ==%s\n' "$c_bold$c_cyan" "$1" "$c_off"
    fi
    [[ -z ${2:-} ]] || printf '%s%s%s\n' "$c_dim" "$2" "$c_off"
}
sub() { printf '\n%s%s%s\n' "$c_bold" "$1" "$c_off"; }
kv() { printf '  %s%-14s%s %s\n' "$c_dim" "$1" "$c_off" "$2"; }
indent() { sed 's/^/  /'; }
tips_begin() { printf '\n%sLearn it: run these yourself (read-only)%s\n' "$c_bold" "$c_off"; }
tip() { printf '  %s$ %s%s  %s# %s%s\n' "$c_grn" "$1" "$c_off" "$c_dim" "$2" "$c_off"; }

human_kb() {
    awk -v k="${1:-0}" 'BEGIN {
        split("KiB MiB GiB TiB PiB", u, " "); i = 1
        while (k >= 1024 && i < 5) { k /= 1024; i++ }
        printf (i == 1 ? "%.0f %s" : "%.1f %s"), k, u[i]
    }'
}

human_age() {
    local s=${1:-0}
    if ((s >= 86400)); then printf '%dd %dh' "$((s / 86400))" "$((s % 86400 / 3600))"
    elif ((s >= 3600)); then printf '%dh %dm' "$((s / 3600))" "$((s % 3600 / 60))"
    else printf '%dm' "$((s / 60))"
    fi
}

# Findings are the heart of the report: what is wrong, why it matters, what to look at next.
# Callers set fid (a stable id) and ftarget (what it is about) for --json, so tools can act on
# a finding without reading its English. Never rename an id: that breaks whatever relies on it.
F_N=0 F_CRIT=0 F_WARN=0 F_INFO=0
finding() {
    F_SEV[F_N]=$1 F_AREA[F_N]=$2 F_TITLE[F_N]=$3 F_WHY[F_N]=$4 F_NEXT[F_N]=${5:-}
    F_ID[F_N]=${fid:-unknown} F_TARGET[F_N]=${ftarget:-}
    ((F_N += 1))
    case $1 in
        CRIT) ((F_CRIT += 1)) ;;
        WARN) ((F_WARN += 1)) ;;
        *) ((F_INFO += 1)) ;;
    esac
}

badge() {
    if [[ $glyph_mode == utf8 ]]; then
        case $1 in
            CRIT) printf '%s%s CRIT%s' "$c_red$c_bold" "$g_crit" "$c_off" ;;
            WARN) printf '%s%s WARN%s' "$c_yel$c_bold" "$g_warn" "$c_off" ;;
            OK) printf '%s%s OK%s  ' "$c_grn$c_bold" "$g_ok" "$c_off" ;;
            *) printf '%s%s INFO%s' "$c_cyan" "$g_tool" "$c_off" ;;
        esac
        return 0
    fi
    case $1 in
        CRIT) printf '%s[CRIT]%s' "$c_red$c_bold" "$c_off" ;;
        WARN) printf '%s[WARN]%s' "$c_yel$c_bold" "$c_off" ;;
        OK) printf '%s[ OK ]%s' "$c_grn$c_bold" "$c_off" ;;
        *) printf '%s[INFO]%s' "$c_cyan" "$c_off" ;;
    esac
}

# show_findings [area|area] prints every finding, most severe first, optionally for some areas.
show_findings() {
    local area=${1:-} sev i shown=0
    for sev in CRIT WARN INFO; do
        for ((i = 0; i < F_N; i++)); do
            [[ ${F_SEV[i]} == "$sev" ]] || continue
            [[ -z $area || ${F_AREA[i]} =~ ^($area)$ ]] || continue
            printf '  %s %s %s(%s)%s\n' "$(badge "$sev")" "${F_TITLE[i]}" "$c_dim" "${F_AREA[i]}" "$c_off"
            printf '         Why: %s\n' "${F_WHY[i]}"
            [[ -z ${F_NEXT[i]} ]] || printf '         Next: %s%s%s\n' "$c_grn" "${F_NEXT[i]}" "$c_off"
            ((shown += 1))
        done
    done
    if ((shown == 0)); then printf '  %s Nothing to report here.\n' "$(badge OK)"; fi
}

# The first screen stays short: most severe titles only, details live in Problems.
show_top_findings() {
    local limit=$1 sev i shown=0
    for sev in CRIT WARN; do
        for ((i = 0; i < F_N; i++)); do
            [[ ${F_SEV[i]} == "$sev" ]] || continue
            ((shown += 1))
            ((shown <= limit)) || continue
            printf '  %s %s\n' "$(badge "$sev")" "${F_TITLE[i]}"
        done
    done
    ((shown <= limit)) || printf '  and %d more\n' "$((shown - limit))"
    if ((shown > 0)); then printf '  %sWhy each one matters and what to do: open Problems (--problems)%s\n' "$c_dim" "$c_off"; fi
}

progress() {
    if [[ ${tui_active:-no} == yes ]]; then printf '\r\033[K  Scanning: %s' "$1" >&9
    elif [[ -t 2 ]]; then printf '\r\033[K  Scanning: %s' "$1" >&2
    fi
}

# sig_list STATUS_REGEX LABEL_REGEX [GROUP] joins matching signature labels with commas.
sig_list() {
    printf '%s' "$sig_rows" | awk -F '|' -v s="^($1)\$" -v l="$2" -v g="${3:-}" '
        $3 ~ s && $2 ~ l && (g == "" || $1 == g) { out = out (out == "" ? "" : ", ") $2 }
        END { print out }'
}

# ---------------------------------------------------------------------------
# Host identity
# ---------------------------------------------------------------------------
check_host() {
    local line vendor product release=/etc/os-release
    H_NAME=$(hostname 2>/dev/null) || H_NAME=
    [[ -n $H_NAME || ! -r /proc/sys/kernel/hostname ]] || read -r H_NAME < /proc/sys/kernel/hostname
    [[ -r $release ]] || release=/usr/lib/os-release
    H_OS=unknown
    if [[ -r $release ]]; then
        while IFS= read -r line; do
            if [[ $line == PRETTY_NAME=* ]]; then
                H_OS=${line#*=} H_OS=${H_OS#\"} H_OS=${H_OS%\"}
                break
            fi
        done < "$release"
    fi
    H_KERNEL=$(uname -r 2>/dev/null) H_ARCH=$(uname -m 2>/dev/null)
    H_CPUS=$(getconf _NPROCESSORS_ONLN 2>/dev/null)
    [[ $H_CPUS =~ ^[1-9][0-9]*$ ]] || H_CPUS=1
    H_MODEL=$(awk -F ': *' '/^model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null)
    H_UPTIME=0
    if [[ -r /proc/uptime ]]; then read -r line _ < /proc/uptime; H_UPTIME=${line%%.*}; fi
    H_INIT=unknown
    [[ ! -r /proc/1/comm ]] || read -r H_INIT < /proc/1/comm

    H_CONTAINER=
    if [[ -f /.dockerenv ]]; then H_CONTAINER=Docker
    elif [[ -f /run/.containerenv ]]; then H_CONTAINER=Podman
    elif [[ -n ${KUBERNETES_SERVICE_HOST:-} ]]; then H_CONTAINER='Kubernetes pod'
    fi

    vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null) || vendor=
    product=$(cat /sys/class/dmi/id/product_name 2>/dev/null) || product=
    H_VIRT=
    if has systemd-detect-virt; then H_VIRT=$(run_t 3 systemd-detect-virt 2>/dev/null) || H_VIRT=; fi
    [[ $H_VIRT != none ]] || H_VIRT=bare-metal
    if [[ -z $H_VIRT ]]; then
        if grep -qs '^flags.* hypervisor' /proc/cpuinfo; then H_VIRT=virtual-machine; else H_VIRT=unknown; fi
    fi
    case "$vendor $product" in
        *Amazon*) H_PLACE='Amazon AWS' ;;
        *Google*) H_PLACE='Google Cloud' ;;
        *'Microsoft Corporation'*'Virtual Machine'*) H_PLACE='Microsoft Azure or Hyper-V' ;;
        *DigitalOcean*) H_PLACE=DigitalOcean ;;
        *Hetzner*) H_PLACE=Hetzner ;;
        *OVH*) H_PLACE=OVHcloud ;;
        *Linode*|*Akamai*) H_PLACE=Linode ;;
        *Vultr*) H_PLACE=Vultr ;;
        *Alibaba*) H_PLACE='Alibaba Cloud' ;;
        *Oracle*) H_PLACE='Oracle Cloud' ;;
        *VMware*) H_PLACE=VMware ;;
        *Proxmox*) H_PLACE=Proxmox ;;
        *) H_PLACE=${product:-} ;;
    esac

    H_IP=
    if has ip; then
        H_IP=$(run_t 3 ip -4 route get 1.1.1.1 2>/dev/null |
            awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }')
    fi
    H_TIME=$(date '+%Y-%m-%d %H:%M %Z' 2>/dev/null)
    H_NTP=
    if has timedatectl; then
        H_NTP=$(run_t 3 timedatectl show -p NTPSynchronized --value 2>/dev/null) || H_NTP=
    fi
    check_eol
    H_PKG=unknown
    for line in apt-get dnf yum zypper apk pacman opkg; do
        if has "$line"; then H_PKG=$line; break; fi
    done
    if [[ $H_NTP == no ]]; then
        fid=clock-unsynced finding WARN host 'Server clock is not synchronized' \
            'TLS, logins, logs and clusters all break in odd ways when clocks drift.' 'timedatectl status'
    fi
    if ((LHA_UID != 0)); then
        fid=not-root finding INFO host 'Running without root, so this report is partial' \
            'Process owners, firewall rules, certificates and some logs stay hidden.' 'sudo bash linux-host-audit.sh'
    fi
}

# Last month of free security updates. Newer or unlisted systems simply show nothing.
check_eol() {
    local line
    H_EOL= H_OS_ID= H_OS_VERSION=
    [[ -r /etc/os-release ]] || return 0
    while IFS= read -r line; do
        case $line in
            ID=*) H_OS_ID=${line#ID=} H_OS_ID=${H_OS_ID//\"/} ;;
            VERSION_ID=*) H_OS_VERSION=${line#VERSION_ID=} H_OS_VERSION=${H_OS_VERSION//\"/} ;;
        esac
    done < /etc/os-release
    case $H_OS_ID:${H_OS_VERSION%%.*} in
        amzn:2) H_EOL=2026-06 ;;
        almalinux:8|rocky:8|ol:8|rhel:8|cloudlinux:8) H_EOL=2029-03 ;;
        almalinux:9|rocky:9|ol:9|rhel:9|cloudlinux:9) H_EOL=2032-05 ;;
        centos:6) H_EOL=2020-11 ;;
        centos:7|rhel:7|cloudlinux:7) H_EOL=2024-06 ;;
        centos:8) H_EOL=2021-12 ;;
        debian:8) H_EOL=2020-06 ;;
        debian:9) H_EOL=2022-06 ;;
        debian:10) H_EOL=2024-06 ;;
        debian:11) H_EOL=2026-08 ;;
        debian:12) H_EOL=2028-06 ;;
        debian:13) H_EOL=2030-06 ;;
    esac
    case $H_OS_ID:$H_OS_VERSION in
        ubuntu:14.04*) H_EOL=2019-04 ;;
        ubuntu:16.04*) H_EOL=2021-04 ;;
        ubuntu:18.04*) H_EOL=2023-05 ;;
        ubuntu:20.04*) H_EOL=2025-05 ;;
        ubuntu:22.04*) H_EOL=2027-04 ;;
        ubuntu:24.04*) H_EOL=2029-04 ;;
        ubuntu:26.04*) H_EOL=2031-04 ;;
    esac
    if [[ -n $H_EOL && $H_EOL < $(date +%Y-%m) ]]; then
        fid=os-eol ftarget="$H_OS" finding WARN security "$H_OS no longer gets free security updates" \
            "Standard support ended in $H_EOL, so new holes stay open. Plan an upgrade." 'cat /etc/os-release'
    fi
}

# ---------------------------------------------------------------------------
# CPU, memory and disk health
# ---------------------------------------------------------------------------
disk_rows() {
    run_t 5 df -lP "$@" 2>/dev/null | awk 'NR > 1 {
        fs = $1; mnt = $NF; use = $5; sub(/%/, "", use)
        if (fs ~ /^(tmpfs|devtmpfs|overlay|shm|none|udev|efivarfs|squashfs|cgroup.*)$/ || fs ~ /^\/dev\/loop/) next
        if (mnt ~ /^\/(proc|sys|dev|run|snap|var\/lib\/(docker|containers|kubelet))(\/|$)/) next
        if (use !~ /^[0-9]+$/) next
        print mnt, use, $2, $4
    }'
}

check_resources() {
    local key value rest mnt use size free pct line mem_total=0 mem_avail=0 mem_old=0 swap_total=0 swap_free=0
    metrics_snapshot
    sleep 1
    metrics_snapshot
    R_CPU=$cpu_pct R_STEAL=$steal_pct R_WAIT=$wait_pct
    read -r R_LOAD1 R_LOAD5 R_LOAD15 rest < /proc/loadavg 2>/dev/null || R_LOAD1=0 R_LOAD5=0 R_LOAD15=0
    if [[ -r /proc/meminfo ]]; then
        while read -r key value rest; do
            case $key in
                MemTotal:) mem_total=$value ;;
                MemAvailable:) mem_avail=$value ;;
                SwapTotal:) swap_total=$value ;;
                SwapFree:) swap_free=$value ;;
                MemFree:|Buffers:|Cached:) mem_old=$((mem_old + value)) ;;
            esac
        done < /proc/meminfo
    fi
    # Kernels before 3.14 have no MemAvailable.
    ((mem_avail > 0)) || mem_avail=$mem_old
    R_MEM_TOTAL=$mem_total R_MEM_AVAIL=$mem_avail R_SWAP_TOTAL=$swap_total
    R_SWAP_USED=$((swap_total - swap_free)) R_MEM_PCT=$ram_pct

    R_PER_CORE=$(awk -v l="$R_LOAD1" -v c="$H_CPUS" 'BEGIN { printf "%d", 100 * l / c }')
    if ((R_PER_CORE >= 400)); then
        fid=load-high finding CRIT resources "Load is $R_LOAD1 on $H_CPUS CPU cores" \
            'Far more work is waiting than the CPUs can run, so everything feels slow.' 'top -o %CPU'
    elif ((R_PER_CORE >= 200)); then
        fid=load-high finding WARN resources "Load is $R_LOAD1 on $H_CPUS CPU cores" \
            'Work is queueing. It can be CPU, or processes stuck waiting for disk.' 'top -o %CPU'
    fi
    if ((R_STEAL >= 10)); then
        fid=cpu-steal finding WARN resources "CPU steal is $R_STEAL%" \
            'The hypervisor is giving your CPU time to other VMs. The host may be oversold.' 'vmstat 1 5'
    fi
    if ((R_WAIT >= 25)); then
        fid=io-wait finding WARN resources "CPU spends $R_WAIT% of its time waiting for disk" \
            'The disk is the bottleneck, not the CPU.' 'iostat -x 1 3'
    fi
    if ((mem_total > 0)); then
        pct=$((100 * mem_avail / mem_total))
        if ((pct < 5)); then
            fid=memory-low finding CRIT resources "Only $pct% of RAM is available" \
                'The kernel may start killing processes (OOM killer) at any moment.' 'ps aux --sort=-rss | head'
        elif ((pct < 10)); then
            fid=memory-low finding WARN resources "Only $pct% of RAM is available" \
                'Little memory is left for traffic spikes or disk cache.' 'ps aux --sort=-rss | head'
        fi
    fi
    if ((swap_total > 0 && R_SWAP_USED * 100 / swap_total >= 50)); then
        fid=swap-high finding WARN resources "$((R_SWAP_USED * 100 / swap_total))% of swap is in use" \
            'Heavy swap use means RAM ran short, and swap is far slower than RAM.' 'free -h'
    fi

    R_DISKS=$(disk_rows)
    while read -r mnt use size free; do
        [[ -n $mnt ]] || continue
        if ((use >= 95)); then
            fid=disk-full ftarget="$mnt" finding CRIT disk "Disk $mnt is $use% full" \
                'At 100% databases stop, logs fail and services crash.' "du -xh $mnt --max-depth=2 | sort -h | tail"
        elif ((use >= 85)); then
            fid=disk-full ftarget="$mnt" finding WARN disk "Disk $mnt is $use% full" \
                "$(human_kb "$free") left. Plan a cleanup before it fills." "du -xh $mnt --max-depth=2 | sort -h | tail"
        fi
    done <<< "$R_DISKS"
    while read -r mnt use size free; do
        [[ -n $mnt ]] || continue
        if ((use >= 90)); then
            fid=inodes-full ftarget="$mnt" finding CRIT disk "Disk $mnt used $use% of its inodes" \
                'New files fail with "no space left" even though free space remains.' \
                "du --inodes -x $mnt --max-depth=2 | sort -n | tail"
        fi
    done <<< "$(disk_rows -i)"

    if [[ -z $H_CONTAINER && -r /proc/mounts ]]; then
        while read -r mnt; do
            [[ -z $mnt ]] || fid=fs-readonly ftarget="$mnt" finding CRIT disk "Filesystem $mnt is mounted read-only" \
                'Linux usually does this after disk errors. Writes will fail.' 'dmesg | tail -30'
        done <<< "$(awk '$3 ~ /^(ext[234]|xfs|btrfs)$/ && $4 ~ /^ro(,|$)/ { print $2 }' /proc/mounts)"
    fi
    if [[ -r /proc/mdstat ]] && grep -q '\[[U]*_[U_]*\]' /proc/mdstat; then
        fid=raid-degraded finding CRIT disk 'A software RAID array is degraded' \
            'One disk already failed. Another failure can lose the data.' 'cat /proc/mdstat'
    fi
    # zpool loads the zfs kernel module when it is not there, so only ask where it already is.
    if has zpool && [[ -d /sys/module/zfs ]]; then
        line=$(run_t 5 zpool status -x 2>/dev/null) || line=
        if [[ -n $line && $line != *'all pools are healthy'* && $line != 'no pools available'* ]]; then
            fid=zfs-unhealthy finding CRIT disk 'A ZFS pool is not healthy' 'ZFS reports a problem with a pool.' 'zpool status -x'
        fi
    fi

    R_OOM=$(awk '$1 == "oom_kill" { print $2 }' /proc/vmstat 2>/dev/null)
    # smartctl -H only asks the drive for its verdict.
    if has smartctl && ((LHA_UID == 0)) && [[ -z $H_CONTAINER ]]; then
        for mnt in /dev/sd[a-z] /dev/nvme[0-9]n1; do
            [[ -b $mnt ]] || continue
            line=$(run_t 8 smartctl -H "$mnt" 2>/dev/null)
            if [[ $line == *FAILED* ]]; then
                fid=smart-failing ftarget="$mnt" finding CRIT disk "Drive $mnt reports that it is failing" \
                    'SMART predicts failure. Copy your data off and replace the drive.' "smartctl -a $mnt"
            fi
        done
    fi
    if [[ -r /proc/sys/fs/file-nr ]]; then
        read -r key rest value < /proc/sys/fs/file-nr
        if [[ $value =~ ^[0-9]+$ ]] && ((value > 0 && key * 100 / value >= 80)); then
            fid=file-limit finding CRIT resources 'Open file limit is almost reached' \
                'Services will fail with "too many open files".' 'cat /proc/sys/fs/file-nr'
        fi
    fi
    if [[ -r /proc/sys/net/netfilter/nf_conntrack_count && -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        read -r key < /proc/sys/net/netfilter/nf_conntrack_count
        read -r value < /proc/sys/net/netfilter/nf_conntrack_max
        if ((value > 0 && key * 100 / value >= 80)); then
            fid=conntrack-full finding CRIT network 'Connection tracking table is almost full' \
                'When full, the kernel silently drops new connections.' 'sysctl net.netfilter.nf_conntrack_count'
        fi
    fi
    # cat rides over a process that vanishes. awk alone stops there on mawk.
    R_ZOMBIES=$(cat /proc/[0-9]*/stat 2>/dev/null | awk '{ sub(/^.*\) /, ""); if ($1 == "Z") n++ } END { print n + 0 }')
    if ((R_ZOMBIES >= 20)); then
        fid=zombies finding WARN resources "$R_ZOMBIES zombie processes" \
            'A parent process is not cleaning up its children, a sign of a buggy app.' 'ps -eo stat,ppid,comm | grep "^Z"'
    fi
}

view_resources() {
    local mnt use size free
    title 'CPU, RAM and disk' 'How busy the machine is right now, and what is using it.'
    kv CPU "$H_CPUS cores, $R_CPU% busy, $R_WAIT% waiting for disk, $R_STEAL% stolen by hypervisor"
    kv Load "$R_LOAD1 / $R_LOAD5 / $R_LOAD15 (1, 5, 15 min). Around $H_CPUS means fully used."
    kv RAM "$(human_kb "$((R_MEM_TOTAL - R_MEM_AVAIL))") used of $(human_kb "$R_MEM_TOTAL") ($R_MEM_PCT%)"
    if ((R_SWAP_TOTAL > 0)); then kv Swap "$(human_kb "$R_SWAP_USED") used of $(human_kb "$R_SWAP_TOTAL")"
    else kv Swap 'none configured'
    fi
    sub 'Disks'
    printf '  %-28s %6s %12s %12s\n' MOUNT USED SIZE FREE
    while read -r mnt use size free; do
        [[ -z $mnt ]] || printf '  %-28s %5s%% %12s %12s\n' "$mnt" "$use" "$(human_kb "$size")" "$(human_kb "$free")"
    done <<< "$R_DISKS"
    if has ps; then
        sub 'Top processes by CPU'
        ps -eo pcpu=,pmem=,user=,comm= --sort=-pcpu 2>/dev/null | head -n 8 | clean | indent
        sub 'Top processes by memory'
        ps -eo pmem=,pcpu=,user=,comm= --sort=-pmem 2>/dev/null | head -n 8 | clean | indent
    fi
    if [[ -d /var/log ]]; then
        sub 'Biggest log files'
        ls -lS /var/log 2>/dev/null | clean | awk '$1 ~ /^-/ && n++ < 5 { printf "  %10.1f MiB  %s\n", $5 / 1048576, $NF }'
    fi
    sub 'Problems found here'
    show_findings 'resources|disk'
    tips_begin
    tip 'top' 'live process list (press q to leave)'
    tip 'free -h' 'memory; look at "available", not "free"'
    tip 'df -h' 'disk space per filesystem'
    tip 'df -i' 'inodes: the number of files a disk can hold'
    tip 'vmstat 1 5' 'CPU, memory and I/O, once a second'
}

# ---------------------------------------------------------------------------
# Ports, firewall and network: this finds any application, known or not
# ---------------------------------------------------------------------------
# ss asks the kernel through sock_diag, and the kernel then loads these modules if it can.
# So ss is only used where they are in already, or do not exist as modules at all.
ss_quiet() {
    local module
    for module in "$@"; do
        [[ ! -d $LHA_ROOT/sys/module/$module ]] || continue
        # A container cannot see the module list, and the load would happen on its host.
        [[ -z ${H_CONTAINER:-} ]] || return 1
        if grep -qs "/$module\.ko" "$LHA_ROOT/lib/modules/$(uname -r)/modules.dep"; then return 1; fi
    done
}

# Socket inode, then owner pid, read from /proc. Links and names only, never arguments.
proc_socket_owners() {
    ls -l /proc/[0-9]*/fd 2>/dev/null | awk '
        /^\/proc\/[0-9]+\/fd:$/ { split($0, p, "/"); pid = p[3]; next }
        match($0, /socket:\[[0-9]+\]$/) { print substr($0, RSTART + 8, RLENGTH - 9), pid }'
}

# Same rows as ss, from the tables the kernel publishes anyway.
proc_listeners() {
    local name
    {
        proc_socket_owners
        for name in tcp tcp6 udp udp6; do
            printf '@ %s\n' "$name"
            cat "$LHA_ROOT/proc/net/$name" 2>/dev/null
        done
    } | awk -v root="$LHA_ROOT" '
        function hex(s,   i, v) {
            v = 0; s = tolower(s)
            for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1
            return v
        }
        function v4(a) { return hex(substr(a, 7, 2)) "." hex(substr(a, 5, 2)) "." hex(substr(a, 3, 2)) "." hex(substr(a, 1, 2)) }
        function v6(a,   out, i, w) {
            if (a == "00000000000000000000000000000000") return "::"
            if (a == "00000000000000000000000001000000") return "::1"
            if (substr(a, 1, 24) == "0000000000000000FFFF0000") return "::ffff:" v4(substr(a, 25, 8))
            out = ""
            for (i = 0; i < 4; i++) {
                w = tolower(substr(a, 8 * i + 1, 8))
                out = out (i ? ":" : "") substr(w, 7, 2) substr(w, 5, 2) ":" substr(w, 3, 2) substr(w, 1, 2)
            }
            return out
        }
        function name_of(pid,   file, text) {
            if (pid in names) return names[pid]
            file = root "/proc/" pid "/comm"
            text = "?"
            if ((getline text < file) <= 0) text = "?"
            close(file)
            gsub(/ /, "_", text)
            names[pid] = text
            return text
        }
        $1 == "@" { table = $2; next }
        table == "" { owner[$1] = $2; next }
        $2 !~ /:/ { next }
        {
            udp = (table ~ /^udp/)
            if (udp ? $4 != "07" : $4 != "0A") next
            split($2, a, ":")
            pid = ($10 in owner) ? owner[$10] : "-"
            print (udp ? "udp" : "tcp"), hex(a[2]), (table ~ /6$/ ? v6(a[1]) : v4(a[1])), (pid == "-" ? "?" : name_of(pid)), pid
        }'
}

net_listeners() {
    local raw
    if has ss && ss_quiet tcp_diag udp_diag && raw=$(run_t 5 ss -lntup 2>/dev/null); then
        awk '$1 ~ /^(tcp|udp)$/ {
            n = split($5, a, ":"); port = a[n]
            addr = substr($5, 1, length($5) - length(port) - 1)
            proc = "?"; pid = "-"
            if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
            if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
            print $1, port, addr, proc, pid
        }' <<< "$raw"
    elif has netstat && raw=$(run_t 5 netstat -lntup 2>/dev/null); then
        awk '$1 ~ /^(tcp|udp)6?$/ {
            n = split($4, a, ":"); port = a[n]
            addr = substr($4, 1, length($4) - length(port) - 1)
            proc = "?"; pid = "-"; last = $NF
            if (split(last, p, "/") == 2) { pid = p[1]; proc = p[2] }
            sub(/6$/, "", $1)
            print $1, port, addr, proc, pid
        }' <<< "$raw"
    else
        proc_listeners
    fi
}

# Established connections, optionally on some local ports. tcp_diag stays out of it this way,
# and old ss has no -H anyway.
tcp_count() {
    local state=$1 from=${2:-0} to=${3:-65535}
    shift 3
    cat "$LHA_ROOT/proc/net/tcp" "$LHA_ROOT/proc/net/tcp6" 2>/dev/null | awk -v state="$state" -v from="$from" -v to="$to" -v ports=" $* " '
        function hex(s,   i, v) {
            v = 0; s = tolower(s)
            for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1
            return v
        }
        $4 == state {
            split($2, a, ":"); p = hex(a[2])
            if (p < from + 0 || p > to + 0) next
            if (ports != "  " && !index(ports, " " p " ")) next
            n++
        }
        END { print n + 0 }'
}

# Which local port a program holds, and which program holds a port.
port_of() { awk -v names=" $* " '$1 == "tcp" && index(names, " " $5 " ") { print $2; exit }' <<< "$NET_ROWS"; }
port_owner() { awk -v p="$1" '$1 == "tcp" && $2 == p { print $5; exit }' <<< "$NET_ROWS"; }

# NET_ROWS: proto port scope addr process pid, one row per proto/port/process.
net_collect() {
    NET_ROWS=$(net_listeners | awk '
        function scope(a) {
            sub(/%.*/, "", a); gsub(/[][]/, "", a)
            # Java and others bind a v4 address in v6 form.
            sub(/^::ffff:/, "", a)
            if (a ~ /^127\./ || a == "::1") return 1
            if (a ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|f[cd]|fe80)/) return 2
            return 3
        }
        {
            k = $1 " " $2 " " $4
            s = scope($3)
            if (!(k in best) || s > best[k]) { best[k] = s; addr[k] = $3; pid[k] = $5 }
        }
        END {
            name[1] = "local"; name[2] = "private"; name[3] = "public"
            for (k in best) {
                split(k, f, " ")
                print f[1], f[2], name[best[k]], addr[k], f[3], pid[k]
            }
        }' | sort -k2,2n -k1,1)
}

port_name() {
    case $1 in
        20|21) REPLY='FTP file transfer' ;;
        81|444) REPLY='Web server behind a proxy' ;;
        783) REPLY='SpamAssassin spam filter' ;;
        2077|2078|2079|2080|2091) REPLY='cPanel WebDAV and calendars' ;;
        2095|2096) REPLY='cPanel webmail' ;;
        4190) REPLY='Mail filter rules (ManageSieve)' ;;
        22) REPLY='SSH remote login' ;;
        25|465|587) REPLY='Mail sending (SMTP)' ;;
        53) REPLY=DNS ;;
        80|8080|8000|8008) REPLY='Web (HTTP)' ;;
        110|143|993|995) REPLY='Mailbox (POP3/IMAP)' ;;
        111) REPLY='RPC portmapper (NFS helper)' ;;
        123) REPLY='Time sync (NTP)' ;;
        443|8443) REPLY='Web (HTTPS)' ;;
        445|139) REPLY='Windows file sharing (SMB)' ;;
        1433) REPLY='Microsoft SQL Server' ;;
        1521) REPLY='Oracle Database' ;;
        2049) REPLY='NFS file sharing' ;;
        2181) REPLY='ZooKeeper' ;;
        3128) REPLY='Squid proxy' ;;
        4222) REPLY='NATS messaging' ;;
        6432) REPLY='PgBouncer pool' ;;
        7000|7001|9042) REPLY='Cassandra' ;;
        8086) REPLY='InfluxDB' ;;
        8123) REPLY='ClickHouse HTTP' ;;
        9092) REPLY='Kafka' ;;
        15672) REPLY='RabbitMQ web console' ;;
        24007) REPLY='GlusterFS' ;;
        25672) REPLY='RabbitMQ cluster' ;;
        2082|2083|2086|2087) REPLY=cPanel/WHM ;;
        2375) REPLY='Docker API WITHOUT encryption' ;;
        2376) REPLY='Docker API (TLS)' ;;
        2379|2380) REPLY='etcd (Kubernetes database)' ;;
        3000) REPLY='App or Grafana' ;;
        3306) REPLY=MySQL/MariaDB ;;
        3389) REPLY='Remote desktop (RDP)' ;;
        5432) REPLY=PostgreSQL ;;
        5672) REPLY=RabbitMQ ;;
        5900|5901) REPLY='VNC remote screen' ;;
        6379) REPLY=Redis/Valkey ;;
        6443) REPLY='Kubernetes API' ;;
        8006) REPLY='Proxmox web UI' ;;
        8083) REPLY='Hosting panel' ;;
        8888) REPLY='aaPanel or notebook' ;;
        9000) REPLY='PHP-FPM or Portainer' ;;
        9090) REPLY='Prometheus or Cockpit' ;;
        9100) REPLY='Node exporter metrics' ;;
        9200|9300) REPLY=Elasticsearch/OpenSearch ;;
        10250) REPLY='Kubelet (Kubernetes node)' ;;
        11211) REPLY=Memcached ;;
        19999) REPLY=Netdata ;;
        27017) REPLY=MongoDB ;;
        *) REPLY= ;;
    esac
}

firewall_state() {
    local out count
    NET_FW='none detected' NET_FW_ON=no
    if has ufw && out=$(run_t 5 ufw status 2>/dev/null) && [[ -n $out ]]; then
        if [[ $out == *'Status: active'* ]]; then NET_FW='UFW active' NET_FW_ON=yes; return 0; fi
    fi
    if has firewall-cmd && [[ $(run_t 5 firewall-cmd --state 2>/dev/null) == running ]]; then
        NET_FW='firewalld running' NET_FW_ON=yes
        return 0
    fi
    if [[ $sig_rows == *'|ConfigServer Firewall (CSF/LFD)|RUNNING|'* ]]; then
        NET_FW='CSF running' NET_FW_ON=yes
        return 0
    fi
    if ((LHA_UID != 0)); then NET_FW='unknown (needs root)' NET_FW_ON=unknown; return 0; fi
    # Both tools can make the kernel load their module, so only ask when it is already loaded.
    if has nft && [[ -d /sys/module/nf_tables ]]; then
        count=$(run_t 5 nft list ruleset 2>/dev/null | grep -c 'drop\|reject')
        if ((count > 0)); then NET_FW="nftables ($count drop or reject rules)" NET_FW_ON=yes; return 0; fi
    fi
    if has iptables && [[ -n $(cat /proc/net/ip_tables_names 2>/dev/null) ]]; then
        count=$(run_t 5 iptables -S 2>/dev/null | grep -c -- '-P INPUT DROP\|-j DROP\|-j REJECT')
        if ((count > 0)); then NET_FW="iptables ($count drop or reject rules)" NET_FW_ON=yes; return 0; fi
    fi
}

check_network() {
    local proto port scope addr proc pid
    net_collect
    firewall_state
    NET_PUBLIC=0 NET_TOTAL=0
    local unknown=0
    while read -r proto port scope addr proc pid; do
        [[ -n $proto ]] || continue
        ((NET_TOTAL += 1))
        [[ $scope == public ]] || continue
        ((NET_PUBLIC += 1))
        port_name "$port"
        if [[ -z $REPLY ]] && ((port < 32768)) && ((unknown < 5)); then
            ((unknown += 1))
            fid=port-unknown ftarget="$port/$proto" finding INFO network "Port $port/$proto is open to the world: $proc" \
                'This tool does not recognize it. Make sure you know why it is open.' "ss -lntup | grep :$port"
        fi
        case $port in
            2375)
                fid=docker-api-open ftarget=2375 finding CRIT security 'Docker API is open without encryption on port 2375' \
                    'Anyone who reaches it gets root on this server.' 'ss -lntp | grep 2375' ;;
            6379|11211|27017|9200|2379|5900|5901|3306|5432|1433|2181|8086|8123|9042|9092|5672|15672)
                port_name "$port"
                if [[ $NET_FW_ON == yes ]]; then
                    fid=db-listens-all ftarget="$port" finding INFO security "$REPLY listens on all interfaces (port $port)" \
                        "Firewall reported: $NET_FW. Confirm it really blocks this port." "ss -lntp | grep :$port"
                else
                    fid=db-exposed ftarget="$port" finding WARN security "$REPLY is reachable from the network (port $port)" \
                        'No active firewall was seen, and internet-exposed databases get attacked.' "ss -lntp | grep :$port"
                fi ;;
        esac
    done <<< "$NET_ROWS"
    if has ip && [[ -z $(run_t 3 ip route show default 2>/dev/null) ]] &&
        [[ -z $(run_t 3 ip -6 route show default 2>/dev/null) ]]; then
        fid=no-default-route finding WARN network 'No default route' 'This server cannot reach other networks.' 'ip route'
    fi
    if [[ -r /etc/resolv.conf ]] && ! grep -q '^nameserver' /etc/resolv.conf; then
        fid=no-dns finding WARN network 'No DNS server configured' 'Domain names cannot be resolved.' 'cat /etc/resolv.conf'
    fi
    if [[ $NET_FW_ON == no ]] && ((NET_PUBLIC > 0)) && [[ -z $H_CONTAINER ]]; then
        fid=no-firewall finding WARN security 'No active firewall was found' \
            'Every public port below is open to the world, unless a cloud firewall protects it.' 'ss -lntu'
    fi
}

view_network() {
    local proto port scope addr proc pid
    title 'Ports and network' 'Each open port is a door into a program. This finds apps no list knows about.'
    kv Address "${H_IP:-unknown}"
    kv Firewall "$NET_FW"
    kv Doors "$NET_TOTAL open ports, $NET_PUBLIC reachable from outside this machine"
    sub 'Open ports'
    printf '  %-6s %-5s %-8s %-20s %s\n' PORT PROTO REACH PROCESS MEANING
    while read -r proto port scope addr proc pid; do
        [[ -n $proto ]] || continue
        port_name "$port"
        printf '  %-6s %-5s %-8s %-20.20s %s\n' "$port" "$proto" "$scope" "$proc" "$REPLY"
    done <<< "$NET_ROWS"
    printf '  %sREACH: local = only this machine, private = internal network, public = any network.%s\n' "$c_dim" "$c_off"
    if has ip; then
        sub 'Network interfaces'
        run_t 3 ip -brief address show 2>/dev/null | clean | indent
        sub 'Routes'
        run_t 3 ip route show 2>/dev/null | head -n 12 | clean | indent
    fi
    if has ss; then
        sub 'Connections right now'
        run_t 5 ss -s 2>/dev/null | head -n 3 | clean | indent
    fi
    sub 'Problems found here'
    show_findings network
    tips_begin
    tip 'ss -lntup' 'who listens on which port'
    tip 'ss -tn state established' 'who is connected right now'
    tip 'ip -brief address' 'interfaces and their IPs'
    tip 'ip route' 'where traffic leaves the machine'
    tip 'curl -I http://127.0.0.1' 'ask the local web server a question'
}

# ---------------------------------------------------------------------------
# Services and applications
# ---------------------------------------------------------------------------
check_services() {
    local unit severity reason
    SVC_FAILED= SVC_APPS=
    if [[ $systemd_visible == yes ]]; then
        SVC_FAILED=$(awk '$3 == "failed" { print $1 }' <<< "$active_units")
        SVC_APPS=$(run_t 8 systemctl --system list-units --type=service --state=running \
            --plain --no-legend --no-pager 2>/dev/null | clean | awk '{
                unit = $1; sub(/\.service$/, "", unit)
                if (unit ~ /^(systemd-|dbus|getty@|serial-getty|user@|polkit|cron|crond$|rsyslog|ssh|sshd$|networkd-dispatcher|NetworkManager|wpa_supplicant|ModemManager|multipathd|udisks2|unattended-upgrades|irqbalance|accounts-daemon|atd$|chrony|ntp|snapd|packagekit|qemu-guest-agent|open-vm-tools|vmtoolsd|tuned|auditd|firewalld|lvm2|rpcbind|gssproxy|cloud-|blk-availability|kdump|sssd|fwupd|thermald|haveged|acpid|rtkit|upower|avahi|plymouth|hv-|waagent|walinuxagent|google-|amazon-|ssm-|nscd|sysstat|smartd|mdmonitor|mcelog|rngd|lxcfs|ufw|containerd|docker$|kubelet)/) next
                desc = ""
                for (i = 5; i <= NF; i++) desc = desc " " $i
                printf "%-34s%s\n", unit, desc
            }')
    fi
    while read -r unit; do
        [[ -n $unit ]] || continue
        severity=WARN
        case $unit in nginx*|apache2*|httpd*|sshd*|ssh.service|mysql*|mariadb*|postgresql*|docker*|kubelet*|k3s*)
            severity=CRIT ;;
        esac
        reason=$(run_t 3 systemctl --system show -p Result -p ExecMainStatus -- "$unit" 2>/dev/null | clean | awk -F= '
            $1 == "Result" { r = $2 }
            $1 == "ExecMainStatus" { s = $2 }
            END { if (r != "") { printf "%s", r; if (s + 0 != 0) printf ", exit status %s", s } }')
        fid=service-failed ftarget="$unit" finding "$severity" services "Service $unit has failed" \
            "It is not running. Last result: ${reason:-unknown}." "journalctl -u $unit -n 50 --no-pager"
    done <<< "$SVC_FAILED"
}

app_versions() {
    local tool text
    for tool in nginx httpd apache2 php mariadb mysql psql redis-server node python3 docker; do
        has "$tool" || continue
        # On MariaDB servers the mysql command is the same client.
        if [[ $tool == mysql ]] && has mariadb; then continue; fi
        case $tool in
            nginx|httpd|apache2) text=$(run_t 3 "$tool" -v 2>&1 | head -n 1) ;;
            php) text=$(run_t 4 php -v 2>/dev/null | head -n 1) ;;
            *) text=$(run_t 3 "$tool" --version 2>&1 | head -n 1) ;;
        esac
        [[ -n $text ]] && printf '%-14s %s\n' "$tool" "$text" | clean | cut -c1-76
    done
}

check_mail() {
    local text
    MAIL_QUEUE=
    if [[ -n $(sig_list RUNNING '^Exim') ]]; then
        if has exim; then text=exim; else text=exim4; fi
        has "$text" && MAIL_QUEUE=$(run_t 8 "$text" -bpc 2>/dev/null | clean)
    elif [[ -n $(sig_list RUNNING '^Postfix') ]] && has postqueue; then
        # The summary line also counts long queue ids, which are not plain hex.
        MAIL_QUEUE=$(run_t 8 postqueue -p 2>/dev/null | awk '/^-- / { for (i = 2; i < NF; i++) if ($(i + 1) ~ /^Requests?\.?$/) n = $i } END { print n + 0 }')
    fi
    [[ $MAIL_QUEUE =~ ^[0-9]+$ ]] || MAIL_QUEUE=
    if [[ -n $MAIL_QUEUE ]] && ((MAIL_QUEUE >= 1000)); then
        fid=mail-queue finding WARN services "$MAIL_QUEUE emails are stuck in the mail queue" \
            'Mail is not leaving, or a hacked site is sending spam.' "$(if [[ -n $(sig_list RUNNING '^Exim') ]]; then printf 'exim -bp | head'; else printf 'postqueue -p | head'; fi)"
    fi
    return 0
}

view_apps() {
    local group list line
    title 'Applications and services' 'Everything this server runs, known signature or not.'
    sub 'Recognized software that is running'
    while IFS= read -r group; do
        [[ -n $group ]] || continue
        list=$(sig_list RUNNING . "$group")
        [[ -z $list ]] || printf '  %-34s %s\n' "$group" "$list"
    done <<< "$sig_groups"
    list=$(sig_list 'PRESENT|TRACE' .)
    [[ -z $list ]] || { sub 'Installed but not running'; printf '  %s\n' "$list" | fold -s -w 76; }
    line=$(app_versions)
    [[ -z $line ]] || { sub 'Versions'; printf '%s\n' "$line" | indent; }
    if [[ -n $APP_ROWS ]]; then
        sub 'Official support of the versions in use'
        printf '%s' "$APP_ROWS" | awk -F '|' -v now="$(date +%Y-%m)" '{
            printf "  %-12s %-10s %s %s\n", $1, $2, ($3 < now ? "ended" : "until"), $3 }'
    fi
    if [[ -n $MAIL_QUEUE ]]; then
        sub 'Mail'
        kv Queue "$MAIL_QUEUE messages waiting to be sent"
    fi
    if [[ -n $SVC_APPS ]]; then
        sub 'All application services (system plumbing hidden)'
        printf '%s\n' "$SVC_APPS" | head -n 60 | indent
    fi
    if has supervisorctl; then
        line=$(run_t 5 supervisorctl status 2>/dev/null | clean)
        [[ -z $line ]] || { sub 'Supervisor programs'; printf '%s\n' "$line" | indent; }
    fi
    # "pm2 list" starts a PM2 daemon when none runs, so only ask a daemon that is already alive.
    line=$(cat "${HOME:-/nonexistent}/.pm2/pm2.pid" 2>/dev/null)
    if has pm2 && [[ $line =~ ^[0-9]+$ && -d /proc/$line ]]; then
        line=$(run_t 8 pm2 list --no-color 2>/dev/null | clean)
        [[ -z $line ]] || { sub 'PM2 Node.js apps'; printf '%s\n' "$line" | indent; }
    fi
    if has ps; then
        sub 'Biggest programs by memory, including apps started by hand'
        ps -eo rss=,comm= 2>/dev/null | clean | awk '
            { mem[$2] += $1; n[$2]++ }
            END { for (p in mem) printf "%10d %4d %s\n", mem[p] / 1024, n[p], p }' |
            sort -rn | head -n 12 | awk '{ printf "  %8d MiB  %3d proc  %s\n", $1, $2, $3 }'
    fi
    sub 'Problems found here'
    show_findings services
    tips_begin
    tip 'systemctl list-units --type=service --state=running' 'running services'
    tip 'systemctl --failed' 'services that crashed'
    tip 'systemctl status nginx' 'one service in detail; swap in any name'
    tip 'journalctl -u nginx -n 50' 'the last 50 log lines of a service'
    tip 'ps auxf' 'every process as a tree'
}

# ---------------------------------------------------------------------------
# Docker, Podman and other container or VM platforms
# ---------------------------------------------------------------------------
# Never read container environments or commands here: they routinely hold secrets.
check_containers() {
    local engine rows rc err name image status ports code running stopped bad info names line
    local unhealthy restarting oomed
    CT_N=0 CT_TOTAL_RUN=0 CT_PLATFORMS=
    for engine in docker podman; do
        has "$engine" || continue
        # A first podman call creates its storage, so skip it where it was never used.
        if [[ $engine == podman && ! -d /var/lib/containers/storage/libpod && ! -d ${HOME:-/nonexistent}/.local/share/containers ]]; then
            continue
        fi
        rows=$(run_t 8 "$engine" ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>/dev/null)
        rc=$?
        if ((rc != 0)); then
            err=$(run_t 8 "$engine" ps -q 2>&1 >/dev/null)
            case $err in
                *'permission denied'*)
                    fid=engine-no-access ftarget="$engine" finding INFO containers "No permission to read $engine" \
                        'Run this tool as root, or as a user in the docker group.' 'sudo bash linux-host-audit.sh' ;;
                *'Cannot connect'*|*'Is the docker daemon'*)
                    fid=engine-down ftarget="$engine" finding CRIT containers "$engine is installed but its daemon is down" \
                        'All its containers are stopped.' "systemctl status $engine" ;;
                *)
                    if ((rc == 124)); then
                        fid=engine-hung ftarget="$engine" finding CRIT containers "$engine is not answering" \
                            'The engine is hung; containers may be stuck too.' "systemctl status $engine"
                    fi ;;
            esac
            continue
        fi
        rows=$(printf '%s' "$rows" | clean)
        # podman-docker provides a docker command, so do not count the same containers twice.
        if ((CT_N > 0)) && [[ $rows == "${CT_ROWS[0]}" ]]; then continue; fi
        running=0 stopped=0 unhealthy=0 restarting=0 oomed=0 names=
        while IFS='|' read -r name image status ports; do
            [[ -n $name ]] || continue
            case $status in
                Up*|running*)
                    ((running += 1))
                    names+=" $name"
                    if [[ $status == *unhealthy* ]]; then
                        ((unhealthy += 1))
                        fid=container-unhealthy ftarget="$name" finding CRIT containers "Container $name is unhealthy" \
                            'It runs, but its own health check fails.' "$engine logs --tail 50 $name"
                    fi ;;
                Restarting*)
                    ((restarting += 1))
                    fid=container-restarting ftarget="$name" finding CRIT containers "Container $name keeps restarting" \
                        'It crashes on start, over and over.' "$engine logs --tail 50 $name" ;;
                Dead*)
                    fid=container-dead ftarget="$name" finding CRIT containers "Container $name is dead" \
                        'The engine failed to stop or remove it cleanly.' "$engine inspect $name" ;;
                Exited*)
                    ((stopped += 1))
                    code=${status#*\(} code=${code%%\)*}
                    case $code in
                        0|143) ;;
                        137) fid=container-killed ftarget="$name" finding WARN containers "Container $name was killed (exit 137)" \
                                'Usually out of memory, or a forced stop.' \
                                "$engine inspect -f '{{.State.OOMKilled}}' $name" ;;
                        *) fid=container-exit-error ftarget="$name" finding WARN containers "Container $name stopped with error code $code" \
                                'The program inside exited with a failure.' "$engine logs --tail 50 $name" ;;
                    esac ;;
                *) ((stopped += 1)) ;;
            esac
        done <<< "$rows"
        if [[ -n $names ]]; then
            # shellcheck disable=SC2086 # names are split on purpose
            info=$(run_t 8 "$engine" inspect --format \
                '{{.Name}} {{.HostConfig.Privileged}} {{.State.OOMKilled}} {{.RestartCount}}' $names 2>/dev/null | clean)
            while read -r name bad oomed code; do
                name=${name#/}
                [[ -n $name ]] || continue
                [[ $bad != true ]] || fid=container-privileged ftarget="$name" finding WARN containers "Container $name runs in privileged mode" \
                    'If it is broken into, the attacker effectively gets root on the host.' \
                    "$engine inspect -f '{{.HostConfig.Privileged}}' $name"
                [[ $oomed != true ]] || fid=container-oom ftarget="$name" finding WARN containers "Container $name was killed for memory" \
                    'It hit a memory limit, or the host ran out of RAM.' "$engine stats --no-stream $name"
                if [[ $code =~ ^[0-9]+$ ]] && ((code >= 10)); then
                    fid=container-restart-count ftarget="$name" finding WARN containers "Container $name restarted $code times" \
                        'A healthy container does not need to restart this often.' "$engine logs --tail 50 $name"
                fi
            done <<< "$info"
        fi
        CT_ENGINE[CT_N]=$engine CT_ROWS[CT_N]=$rows
        CT_STATE[CT_N]="$running running, $stopped stopped, $unhealthy unhealthy, $restarting restarting"
        ((CT_N += 1))
        ((CT_TOTAL_RUN += running))
    done
    if has crictl && ((CT_TOTAL_RUN == 0)); then
        line=$(run_t 8 crictl ps -q 2>/dev/null | wc -l | tr -d ' ')
        if [[ $line =~ ^[0-9]+$ ]] && ((line > 0)); then
            CT_ENGINE[CT_N]=crictl CT_ROWS[CT_N]='' CT_STATE[CT_N]="$line running"
            ((CT_N += 1))
            ((CT_TOTAL_RUN += line))
        fi
    fi
    if ((CT_N > 0 && LHA_UID == 0)); then
        while read -r line; do
            [[ -n $line ]] || continue
            fid=container-log-large finding WARN containers "A container log has grown to $line GiB" \
                'Without log rotation, these files quietly fill the disk.' \
                'du -sh /var/lib/docker/containers/* | sort -h | tail'
        done <<< "$(ls -lS /var/lib/docker/containers/*/*-json.log 2>/dev/null | awk 'n++ < 3 && $5 >= 1073741824 { printf "%.1f\n", $5 / 1073741824 }')"
    fi
    # Only ask running daemons: these clients can start a service or write first-run files.
    [[ $processes != *$'\n'lxd$'\n'* ]] || CT_PLATFORMS+=' LXD'
    [[ $processes != *$'\n'incusd$'\n'* ]] || CT_PLATFORMS+=' Incus'
    if [[ $processes == *$'\n'pvedaemon* ]]; then CT_PLATFORMS+=' Proxmox-LXC Proxmox-VM'; fi
    [[ $processes != *$'\n'libvirtd$'\n'* && $processes != *$'\n'virtqemud$'\n'* ]] || CT_PLATFORMS+=' libvirt'
    return 0
}

view_containers() {
    local i engine name image status ports line
    title 'Docker, Podman and other containers' 'A container is an isolated app with its own files. Many can share one server.'
    if ((CT_N == 0)) && [[ -z $CT_PLATFORMS ]]; then
        printf '  No container engine or VM platform found on this server.\n'
    fi
    for ((i = 0; i < CT_N; i++)); do
        engine=${CT_ENGINE[i]}
        sub "$engine: ${CT_STATE[i]}"
        if [[ $engine == crictl ]]; then
            run_t 8 crictl ps -a 2>/dev/null | clean | indent
            continue
        fi
        line=$(run_t 8 "$engine" version --format '{{.Server.Version}}' 2>/dev/null | clean)
        [[ -z $line ]] || kv Version "$line"
        if [[ $engine == docker ]]; then
            line=$(run_t 8 docker info --format '{{.Driver}}, data in {{.DockerRootDir}}, swarm {{.Swarm.LocalNodeState}}' 2>/dev/null | clean)
            [[ -z $line ]] || kv Engine "$line"
        fi
        printf '  %-26s %-32s %s\n' NAME STATUS IMAGE
        while IFS='|' read -r name image status ports; do
            [[ -n $name ]] || continue
            printf '  %-26.26s %-32.32s %s\n' "$name" "$status" "$image"
            [[ -z $ports ]] || printf '  %s%.74s%s\n' "$c_dim" "  ports: $ports" "$c_off"
        done <<< "${CT_ROWS[i]}"
        line=$(run_t 10 "$engine" stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}' 2>/dev/null | clean)
        if [[ -n $line ]]; then
            sub 'Live usage per container'
            printf '%s\n' "$line" | head -n 30 | awk -F '|' '{ printf "  %-26.26s CPU %-8s MEM %-24s NET %s\n", $1, $2, $3, $4 }'
        fi
        line=$(run_t 15 "$engine" system df 2>/dev/null | clean)
        [[ -z $line ]] || { sub 'Disk used by images, containers and volumes'; printf '%s\n' "$line" | indent; }
        line=$(run_t 8 "$engine" network ls --format '{{.Name}} ({{.Driver}})' 2>/dev/null | clean | awk '
            !/^(bridge|host|none) /' | tr '\n' ' ')
        [[ -z $line ]] || kv Networks "$line"
        if [[ $engine == docker ]]; then
            line=$(run_t 8 docker compose ls 2>/dev/null | clean)
            [[ -z $line ]] || { sub 'Compose projects'; printf '%s\n' "$line" | indent; }
            line=$(run_t 8 docker service ls 2>/dev/null | clean)
            [[ -z $line ]] || { sub 'Swarm services'; printf '%s\n' "$line" | indent; }
        fi
    done
    if [[ $CT_PLATFORMS == *LXD* ]]; then sub 'LXD containers'; run_t 8 lxc list 2>/dev/null | clean | indent; fi
    if [[ $CT_PLATFORMS == *Incus* ]]; then sub 'Incus instances'; run_t 8 incus list 2>/dev/null | clean | indent; fi
    if [[ $CT_PLATFORMS == *Proxmox-VM* ]]; then sub 'Proxmox virtual machines'; run_t 8 qm list 2>/dev/null | clean | indent; fi
    if [[ $CT_PLATFORMS == *Proxmox-LXC* ]]; then sub 'Proxmox containers'; run_t 8 pct list 2>/dev/null | clean | indent; fi
    if [[ $CT_PLATFORMS == *libvirt* ]]; then sub 'libvirt virtual machines'; run_t 8 virsh list --all 2>/dev/null | clean | indent; fi
    sub 'Problems found here'
    show_findings containers
    tips_begin
    tip 'docker ps -a' 'all containers, stopped ones too'
    tip 'docker logs --tail 50 NAME' 'what a container printed last'
    tip 'docker stats --no-stream' 'CPU and RAM per container'
    tip 'docker inspect NAME' 'full details (may show secrets, do not paste it around)'
    tip 'docker system df' 'disk used by Docker'
    printf '  %sExit codes: 0 clean stop, 1 app error, 137 killed or out of memory, 139 crash, 143 stopped normally.%s\n' "$c_dim" "$c_off"
}

# ---------------------------------------------------------------------------
# Kubernetes, in any distribution
# ---------------------------------------------------------------------------
ku() { run_t 12 "${KUBE[@]}" --request-timeout=8s "$@" 2>/dev/null; }

kube_find() {
    local cfg user_home='' found=
    KUBE=()
    if has kubectl; then KUBE=(kubectl)
    elif has oc; then KUBE=(oc)
    elif has k3s; then KUBE=(k3s kubectl)
    elif has microk8s; then KUBE=(microk8s kubectl)
    elif has k0s; then KUBE=(k0s kubectl)
    elif [[ -x /var/lib/rancher/rke2/bin/kubectl ]]; then KUBE=(/var/lib/rancher/rke2/bin/kubectl)
    fi
    if [[ -n ${SUDO_USER:-} ]] && has getent; then
        user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi
    for cfg in "${KUBECONFIG:-}" "${HOME:-/root}/.kube/config" "${user_home:-/nonexistent}/.kube/config" \
        /etc/rancher/k3s/k3s.yaml /etc/rancher/rke2/rke2.yaml /etc/kubernetes/admin.conf \
        /var/snap/microk8s/current/credentials/client.config /var/lib/k0s/pki/admin.conf; do
        if [[ -n $cfg && -r $cfg ]]; then found=$cfg; break; fi
    done
    K_CFG=$found
    if ((${#KUBE[@]})) && [[ -n $found && ${KUBE[0]} != microk8s ]]; then KUBE+=(--kubeconfig "$found"); fi
    return 0
}

check_kube() {
    local nodes pods line count f
    K_ON=no K_API=no K_NODES=0 K_READY=0 K_PODS=0 K_BAD=0 K_BAD_ROWS= K_RESTARTS= K_ROLE=
    kube_find
    K_DIST=$(sig_list 'RUNNING|PRESENT|TRACE' '^(Kubernetes node|K3s|MicroK8s|K0s|RKE2|OpenShift)')
    if [[ -z $K_DIST && -z $K_CFG ]]; then
        [[ -z $H_CONTAINER || -z ${KUBERNETES_SERVICE_HOST:-} ]] || K_ON=yes
        [[ $K_ON == yes ]] || return 0
    fi
    K_ON=yes
    if ((${#KUBE[@]} == 0)); then
        fid=kube-no-client finding INFO kubernetes 'Kubernetes parts exist, but there is no kubectl here' \
            'Cluster state cannot be read from this machine.' 'crictl ps'
        return 0
    fi
    if ! nodes=$(ku get nodes --no-headers) || [[ -z $nodes ]]; then
        if [[ -z $K_CFG ]]; then
            K_ROLE='worker node or no credentials'
            fid=kube-no-credentials finding INFO kubernetes 'No cluster credentials on this machine' \
                'This is normal on a worker node. Run this tool on a control-plane node for the full cluster view.' \
                'systemctl status kubelet'
        else
            fid=kube-api-down finding CRIT kubernetes 'Kubernetes API is not answering' \
                'kubectl cannot reach the cluster. Workloads may still run, but nothing can be managed.' \
                "journalctl -u kubelet -n 50 --no-pager"
        fi
        return 0
    fi
    K_API=yes
    nodes=$(printf '%s\n' "$nodes" | clean)
    K_NODES=$(awk 'END { print NR }' <<< "$nodes")
    K_READY=$(awk '$2 ~ /^Ready/ { n++ } END { print n + 0 }' <<< "$nodes")
    if ((K_READY < K_NODES)); then
        while read -r line; do
            [[ -z $line ]] || fid=kube-node-notready ftarget="$line" finding CRIT kubernetes "Node $line is not Ready" \
                'Pods on this node are not being served or scheduled.' "kubectl describe node $line"
        done <<< "$(awk '$2 !~ /^Ready/ { print $1 }' <<< "$nodes")"
    fi
    f=$(ku get nodes -o 'jsonpath={range .items[*]}{.metadata.name}{" "}{range .status.conditions[?(@.status=="True")]}{.type}{" "}{end}{"\n"}{end}' | clean)
    while read -r line; do
        [[ -n $line ]] || continue
        case " $line " in
            *' MemoryPressure '*) fid=kube-node-memory ftarget="${line%% *}" finding CRIT kubernetes "Node ${line%% *} is short of memory" \
                'Kubernetes will start evicting pods.' "kubectl describe node ${line%% *}" ;;
        esac
        case " $line " in
            *' DiskPressure '*) fid=kube-node-disk ftarget="${line%% *}" finding CRIT kubernetes "Node ${line%% *} is short of disk" \
                'Kubernetes will start evicting pods and removing images.' "kubectl describe node ${line%% *}" ;;
        esac
    done <<< "$f"
    pods=$(ku get pods -A --no-headers | clean)
    K_PODS=$(awk 'NF { n++ } END { print n + 0 }' <<< "$pods")
    K_BAD_ROWS=$(awk 'NF >= 5 {
        split($3, r, "/")
        if ($4 == "Completed" || $4 == "Succeeded") next
        if ($4 != "Running" || r[1] + 0 < r[2] + 0) printf "%-22.22s %-40.40s %-6s %-20s %s\n", $1, $2, $3, $4, $5
    }' <<< "$pods")
    K_BAD=$(awk 'NF { n++ } END { print n + 0 }' <<< "$K_BAD_ROWS")
    if ((K_BAD > 0)); then
        fid=kube-pods-unhealthy finding CRIT kubernetes "$K_BAD pods are not healthy" \
            "$(awk '{ print $4 }' <<< "$K_BAD_ROWS" | sort | uniq -c | sort -rn | head -n 4 | awk '{ printf "%s%s x%s", (NR > 1 ? ", " : ""), $2, $1 }')" \
            'kubectl get pods -A | grep -Ev "Running|Completed"'
    fi
    K_RESTARTS=$(awk 'NF >= 5 && $5 ~ /^[0-9]+$/ && $5 + 0 >= 10 {
        printf "%6d  %s/%s\n", $5, $1, $2 }' <<< "$pods" | sort -rn | head -n 10)
    if [[ -n $K_RESTARTS ]]; then
        count=$(awk 'END { print NR }' <<< "$K_RESTARTS")
        fid=kube-pods-restarting finding WARN kubernetes "$count pods restarted 10 times or more" \
            'They may look healthy now, but they keep crashing.' 'kubectl get pods -A --sort-by=.status.containerStatuses[0].restartCount'
    fi
    line=$(ku get deploy -A --no-headers | clean | awk '{ split($3, r, "/"); if (r[1] + 0 < r[2] + 0) print $1 "/" $2 " " $3 }')
    if [[ -n $line ]]; then
        fid=kube-deployments-unready finding CRIT kubernetes "$(awk 'END { print NR }' <<< "$line") deployments lack ready replicas" \
            "$(head -n 3 <<< "$line" | tr '\n' ';')" 'kubectl get deploy -A'
    fi
    line=$(ku get pvc -A --no-headers | clean | awk '$3 != "Bound" { print $1 "/" $2 " " $3 }')
    if [[ -n $line ]]; then
        fid=kube-pvc-unbound finding WARN kubernetes "$(awk 'END { print NR }' <<< "$line") storage claims are not bound" \
            "$(head -n 3 <<< "$line" | tr '\n' ';')" 'kubectl get pvc -A'
    fi
    for f in /etc/kubernetes/pki/apiserver.crt /var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt; do
        [[ -r $f ]] && has openssl || continue
        if ! openssl x509 -checkend $((30 * 86400)) -noout -in "$f" >/dev/null 2>&1; then
            fid=kube-cert-expiring ftarget="$f" finding CRIT kubernetes 'Kubernetes API certificate expires within 30 days' \
                'When it expires the cluster stops accepting commands.' "openssl x509 -enddate -noout -in $f"
        fi
    done
    return 0
}

view_kube() {
    local line
    title 'Kubernetes' 'A cluster runs pods (groups of containers) across nodes (servers).'
    if [[ $K_ON != yes ]]; then printf '  Kubernetes was not found on this server.\n'; return 0; fi
    kv Software "${K_DIST:-kubectl client}"
    kv Credentials "${K_CFG:-none found}"
    if [[ $K_API == yes ]]; then
        kv API answering
        kv Context "$(ku config current-context | clean)"
        kv Nodes "$K_READY of $K_NODES ready"
        kv Pods "$K_PODS total, $K_BAD not healthy"
        sub 'Nodes'
        ku get nodes -o wide | clean | cut -c1-120 | indent
        sub 'Pods per namespace'
        ku get pods -A --no-headers | clean | awk '{ n[$1]++ } END { for (k in n) printf "  %5d  %s\n", n[k], k }' | sort -rn | head -n 20
        if [[ -n $K_BAD_ROWS ]]; then
            sub 'Pods that are not healthy'
            printf '  %-22s %-40s %-6s %-20s %s\n' NAMESPACE POD READY STATUS RESTARTS
            printf '%s\n' "$K_BAD_ROWS" | head -n 30 | indent
        fi
        if [[ -n $K_RESTARTS ]]; then sub 'Most restarted pods'; printf '%s\n' "$K_RESTARTS" | indent; fi
        for line in deploy statefulset daemonset; do
            sub "Workloads: $line"
            ku get "$line" -A | clean | head -n 25 | cut -c1-100 | indent
        done
        sub 'Services reachable from outside'
        ku get svc -A --no-headers | clean | awk '$3 ~ /LoadBalancer|NodePort/ { printf "  %-20.20s %-30.30s %-13s %s\n", $1, $2, $3, $6 }' | head -n 25
        line=$(ku get ingress -A | clean | cut -c1-110)
        [[ -z $line ]] || { sub 'Ingress (web domains)'; printf '%s\n' "$line" | head -n 25 | indent; }
        line=$(ku get pvc -A | clean | cut -c1-110)
        [[ -z $line ]] || { sub 'Storage claims'; printf '%s\n' "$line" | head -n 20 | indent; }
        line=$(ku top nodes | clean)
        if [[ -n $line ]]; then sub 'Live node usage'; printf '%s\n' "$line" | indent
        else printf '\n  Live usage needs metrics-server, which did not answer.\n'; fi
        line=$(ku get events -A --field-selector type=Warning --sort-by=.lastTimestamp | clean | tail -n 15 | cut -c1-130)
        [[ -z $line ]] || { sub 'Latest warning events'; printf '%s\n' "$line" | indent; }
        if has helm; then
            line=$(run_t 10 helm list -A ${K_CFG:+--kubeconfig "$K_CFG"} 2>/dev/null | clean | cut -c1-110)
            [[ -z $line ]] || { sub 'Helm releases'; printf '%s\n' "$line" | head -n 20 | indent; }
        fi
    elif [[ -n $K_ROLE ]]; then
        kv Role "$K_ROLE"
    fi
    if has crictl && [[ $K_API != yes ]]; then
        sub 'Containers on this node'
        run_t 8 crictl ps -a 2>/dev/null | clean | cut -c1-110 | head -n 30 | indent
    fi
    sub 'Problems found here'
    show_findings kubernetes
    tips_begin
    tip 'kubectl get nodes -o wide' 'servers in the cluster'
    tip 'kubectl get pods -A' 'every pod in every namespace'
    tip 'kubectl describe pod NAME -n NS' 'why a pod is stuck: read Events at the bottom'
    tip 'kubectl logs NAME -n NS --previous' 'logs of the crashed attempt'
    tip 'kubectl get events -A --sort-by=.lastTimestamp' 'the cluster timeline'
    tip 'kubectl top pods -A' 'CPU and RAM per pod (needs metrics-server)'
    printf '  %sStatus: CrashLoopBackOff = crashes on start, ImagePullBackOff = cannot download image,%s\n' "$c_dim" "$c_off"
    printf '  %sPending = no node can take it, OOMKilled = out of memory.%s\n' "$c_dim" "$c_off"
}

# ---------------------------------------------------------------------------
# Websites, domains and TLS certificates
# ---------------------------------------------------------------------------
web_conf_files() {
    local f
    for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* /etc/nginx/vhosts.d/* \
        /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/vhost/* /www/server/panel/vhost/nginx/*.conf \
        /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf /etc/httpd/conf/httpd.conf \
        /www/server/panel/vhost/apache/*.conf /var/www/vhosts/system/*/conf/*.conf \
        /etc/apache2/conf/httpd.conf /usr/local/lsws/conf/vhosts/*/*.conf /etc/caddy/Caddyfile; do
        [[ -f $f && -r $f ]] && printf '%s\n' "$f"
    done
}

check_web() {
    local files=() f path end days now cert subject
    W_DOMAINS= W_CERTS= W_SITES= W_CERT_N=0
    while IFS= read -r f; do [[ -z $f ]] || files+=("$f"); done <<< "$(web_conf_files)"
    if ((${#files[@]})); then
        W_DOMAINS=$(awk '
            {
                line = $0; sub(/^[ \t]+/, "", line); low = tolower(line)
                if (low ~ /^(server_name|servername|serveralias)[ \t]/) {
                    gsub(/;/, "", line)
                    n = split(line, f, /[ \t]+/)
                    for (i = 2; i <= n; i++) {
                        if (f[i] ~ /^[#]/) break
                        if (f[i] ~ /^[A-Za-z0-9*][-A-Za-z0-9.*]*\.[A-Za-z][A-Za-z]+$/ && f[i] !~ /^localhost/) print tolower(f[i])
                    }
                }
            }' "${files[@]}" 2>/dev/null | sort -u | clean)
        W_CERT_PATHS=$(awk '{
            line = $0; sub(/^[ \t]+/, "", line); low = tolower(line)
            if (low ~ /^(ssl_certificate|sslcertificatefile)[ \t]/) {
                split(line, f, /[ \t]+/); p = f[2]; gsub(/[;"'"'"']/, "", p)
                if (p ~ /^\// && p !~ /\$/) print p
            }
        }' "${files[@]}" 2>/dev/null | sort -u)
    else
        W_CERT_PATHS=
    fi
    for f in /etc/letsencrypt/live/*/fullchain.pem; do
        [[ -e $f ]] && W_CERT_PATHS+=$'\n'"$f"
    done
    if has openssl; then
        now=$(date +%s)
        while IFS= read -r cert; do
            [[ -n $cert && -r $cert ]] || continue
            end=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null) || continue
            end=${end#notAfter=}
            subject=$(openssl x509 -noout -subject -in "$cert" 2>/dev/null | sed 's/.*CN *= *//; s/,.*//' | clean)
            days=
            if path=$(date -d "$end" +%s 2>/dev/null); then days=$(((path - now) / 86400)); fi
            ((W_CERT_N += 1))
            W_CERTS+=$(printf '%-36.36s %6s days  %s' "$subject" "${days:-?}" "$end")$'\n'
            if ! openssl x509 -checkend 0 -noout -in "$cert" >/dev/null 2>&1; then
                fid=tls-expired ftarget="$subject" finding CRIT web "TLS certificate expired: $subject" \
                    'Browsers show a security error and visitors leave.' "openssl x509 -enddate -noout -in $cert"
            elif ! openssl x509 -checkend $((7 * 86400)) -noout -in "$cert" >/dev/null 2>&1; then
                fid=tls-expiring-soon ftarget="$subject" finding CRIT web "TLS certificate expires within 7 days: $subject" \
                    'Renewal is probably failing.' 'certbot renew --dry-run'
            elif ! openssl x509 -checkend $((21 * 86400)) -noout -in "$cert" >/dev/null 2>&1; then
                fid=tls-expiring ftarget="$subject" finding WARN web "TLS certificate expires within 21 days: $subject" \
                    "Let's Encrypt renews at 30 days left, so renewal may be failing." 'certbot renew --dry-run'
            fi
        done <<< "$(printf '%s\n' "$W_CERT_PATHS" | sort -u)"
    fi
    for f in /var/www/html /var/www/*/public /var/www/* /home/*/public_html /home/*/domains/*/public_html \
        /var/www/vhosts/*/httpdocs /www/wwwroot/*; do
        [[ -d $f ]] || continue
        if [[ -r $f/wp-includes/version.php ]]; then
            path=$(awk -F "'" '/^\$wp_version/ { print $2 }' "$f/wp-includes/version.php" 2>/dev/null | clean)
            W_SITES+=$(printf '%-44.44s WordPress %s' "$f" "$path")$'\n'
        elif [[ -f $f/artisan ]]; then W_SITES+=$(printf '%-44.44s Laravel' "$f")$'\n'
        elif [[ -f $f/manage.py ]]; then W_SITES+=$(printf '%-44.44s Django' "$f")$'\n'
        elif [[ -f $f/package.json ]]; then W_SITES+=$(printf '%-44.44s Node.js' "$f")$'\n'
        fi
    done
    return 0
}

view_web() {
    local list
    title 'Websites, domains and SSL' 'What this server hosts for the outside world, and whether the padlock is valid.'
    list=$(sig_list 'RUNNING' '^(Nginx|Apache HTTP|LiteSpeed server|OpenLiteSpeed|Caddy|HAProxy|Traefik|Envoy|OpenResty|Tengine|Lighttpd|Apache Tomcat|PHP-FPM|Varnish)')
    kv 'Web stack' "${list:-no web server process seen}"
    if has php; then kv PHP "$(run_t 4 php -v 2>/dev/null | head -n 1 | clean)"; fi
    sub "Domains found in web server config ($(awk 'NF { n++ } END { print n + 0 }' <<< "$W_DOMAINS"))"
    if [[ -n $W_DOMAINS ]]; then printf '%s\n' "$W_DOMAINS" | head -n 40 | indent
    else printf '  None found in the standard config folders.\n'; fi
    sub "TLS certificates ($W_CERT_N)"
    if [[ -n $W_CERTS ]]; then printf '%s' "$W_CERTS" | sort -k2,2n | head -n 40 | indent
    else printf '  None readable. Root access may be needed.\n'; fi
    if [[ -n $W_SITES ]]; then sub 'Web applications found'; printf '%s' "$W_SITES" | head -n 30 | indent; fi
    sub 'Problems found here'
    show_findings web
    tips_begin
    tip 'nginx -T' 'the full nginx config as loaded'
    tip 'apachectl -S' 'Apache sites and which config serves them'
    tip 'curl -I https://example.com' 'response headers from a site'
    tip 'openssl s_client -connect example.com:443 </dev/null' 'see the certificate a site serves'
    tip 'tail -f /var/log/nginx/error.log' 'watch web errors live'
}

# ---------------------------------------------------------------------------
# Databases and caches. Only passwordless local access, never a prompt.
# ---------------------------------------------------------------------------
db_row() { DB_ROWS+=$(printf '%-16s %-14s %s' "$1" "$2" "$3")$'\n'; }

listening() { [[ $NET_ROWS == *"tcp $1 "* ]]; }

check_mysql() {
    local client=mysql out conn max up behind
    has mysql || client=mariadb
    has "$client" || { db_row MySQL/MariaDB "$1" 'no client to query it'; return 0; }
    out=$(run_t 6 "$client" --connect-timeout=3 -NBe \
        "SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Uptime'); SHOW VARIABLES LIKE 'max_connections'" 2>&1)
    if (($? != 0)); then
        case $out in
            *'Access denied'*) db_row MySQL/MariaDB running 'needs a password for details' ;;
            *) db_row MySQL/MariaDB down 'client cannot connect'
               fid=mysql-down finding CRIT data 'MySQL/MariaDB is not answering' 'Apps using it will show database errors.' \
                   'systemctl status mysql mariadb' ;;
        esac
        return 0
    fi
    conn=$(awk '$1 == "Threads_connected" { print $2 }' <<< "$out")
    max=$(awk '$1 == "max_connections" { print $2 }' <<< "$out")
    up=$(awk '$1 == "Uptime" { print $2 }' <<< "$out")
    db_row MySQL/MariaDB running "connections $conn of $max, up $(human_age "${up:-0}")"
    if [[ $conn =~ ^[0-9]+$ && $max =~ ^[1-9][0-9]*$ ]] && ((conn * 100 / max >= 80)); then
        fid=mysql-connections finding WARN data "MySQL uses $conn of $max connections" \
            'At the limit, apps get "too many connections".' "$client -e 'SHOW PROCESSLIST'"
    fi
    # MySQL 8.4 removed the old statement and the old field names. MariaDB before 10.5 and
    # MySQL before 8.0.22 know only those.
    out=$(run_t 6 "$client" --connect-timeout=3 -e 'SHOW REPLICA STATUS\G' 2>/dev/null) || out=
    [[ -n $out ]] || out=$(run_t 6 "$client" --connect-timeout=3 -e 'SHOW SLAVE STATUS\G' 2>/dev/null)
    if [[ -n $out ]]; then
        behind=$(awk '/Seconds_Behind_(Master|Source):/ { print $2 }' <<< "$out")
        db_row 'MySQL replica' "${behind:-?}s behind" "$(awk '/(Slave|Replica)_(IO|SQL)_Running:/ { printf "%s ", $0 }' <<< "$out" | tr -s ' ')"
        if [[ $out == *'Running: No'* ]]; then
            fid=mysql-replication-stopped finding CRIT data 'MySQL replication is stopped' 'This replica no longer receives data.' \
                "$client -e 'SHOW REPLICA STATUS\\G'"
        fi
    fi
}

check_postgres() {
    if ! has pg_isready; then db_row PostgreSQL "$1" 'pg_isready not available'; return 0; fi
    local port
    port=$(port_of postgres)
    if ! run_t 5 pg_isready -t 3 ${port:+-p "$port"} >/dev/null 2>&1; then
        db_row PostgreSQL down 'pg_isready failed'
        fid=postgres-down finding CRIT data 'PostgreSQL is not answering' 'Apps using it will show database errors.' 'systemctl status postgresql'
        return 0
    fi
    db_row PostgreSQL running 'answers; details need the postgres user'
}

check_redis() {
    local name=$1 cli=$2 out role mem clients save port
    has "$cli" || { db_row "$name" running 'no client to query it'; return 0; }
    port=$(port_of "${cli%-cli}-server")
    REDIS_PORT=${port:-6379}
    out=$(run_t 5 "$cli" -h 127.0.0.1 -p "$REDIS_PORT" ping 2>&1)
    case $out in
        *PONG*) ;;
        *NOAUTH*|*'Authentication required'*) db_row "$name" running 'password protected'; return 0 ;;
        *LOADING*) db_row "$name" starting 'loading its data into memory'; return 0 ;;
        *) if [[ -z $port && -n $NET_ROWS ]]; then
               # The listener table names every TCP port, so this one is on a Unix socket only.
               db_row "$name" running 'no TCP port, so it was not queried'
               return 0
           fi
           db_row "$name" down "no answer on 127.0.0.1:$REDIS_PORT"
           fid=redis-down ftarget="$name" finding CRIT data "$name is not answering" 'Caches, sessions and queues using it will fail.' "$cli ping"
           return 0 ;;
    esac
    out=$(run_t 5 "$cli" -h 127.0.0.1 -p "$REDIS_PORT" info 2>/dev/null | tr -d '\r')
    mem=$(awk -F: '$1 == "used_memory_human" { print $2 }' <<< "$out")
    clients=$(awk -F: '$1 == "connected_clients" { print $2 }' <<< "$out")
    role=$(awk -F: '$1 == "role" { print $2 }' <<< "$out")
    save=$(awk -F: '$1 == "rdb_last_bgsave_status" { print $2 }' <<< "$out")
    db_row "$name" running "$role, memory $mem, clients $clients"
    if [[ $save == err ]]; then
        fid=redis-save-failing ftarget="$name" finding CRIT data "$name cannot save to disk" 'A restart would lose recent data, and writes may be refused.' "$cli info persistence"
    fi
    if [[ $NET_ROWS == *"tcp $REDIS_PORT public"* ]]; then
        fid=redis-open ftarget="$name" finding CRIT security "$name answers with no password on a public port" \
            'Anyone can read the data, and this is a well-known way to take over servers.' "ss -lntp | grep $REDIS_PORT"
    fi
}

check_data() {
    local state out line
    DB_ROWS=
    state=$(sig_list 'RUNNING' '^(MariaDB server|MySQL-compatible)')
    if [[ -n $state ]]; then check_mysql running
    elif [[ -n $(sig_list PRESENT '^(MariaDB server|MySQL-compatible)') ]]; then db_row MySQL/MariaDB stopped 'installed, not running'
    fi
    state=$(sig_list 'RUNNING' '^PostgreSQL server')
    if [[ -n $state ]]; then check_postgres running
    elif [[ -n $(sig_list PRESENT '^PostgreSQL server') ]]; then db_row PostgreSQL stopped 'installed, not running'
    fi
    [[ -z $(sig_list RUNNING '^Redis server') ]] || check_redis Redis redis-cli
    [[ -z $(sig_list RUNNING '^Valkey server') ]] || check_redis Valkey valkey-cli
    if [[ -n $(sig_list RUNNING '^(Elasticsearch|OpenSearch)') ]] && has curl; then
        out=$(run_t 5 curl -s -m 3 http://127.0.0.1:9200/_cluster/health 2>/dev/null | clean)
        case $out in
            *'"status":"red"'*) db_row Elasticsearch red 'some data is unavailable'
                fid=search-red finding CRIT data 'Search cluster status is red' 'Some data is unavailable.' 'curl -s localhost:9200/_cluster/health?pretty' ;;
            *'"status":"yellow"'*) db_row Elasticsearch yellow 'data safe, replicas missing' ;;
            *'"status":"green"'*) db_row Elasticsearch green healthy ;;
            *) db_row Elasticsearch running 'needs a password for details' ;;
        esac
    fi
    while read -r line state; do
        [[ -z $line ]] || db_row "$line" "$(listening "$state" && printf listening || printf 'not listening')" "port $state"
    done <<< "$(
        [[ -z $(sig_list RUNNING '^MongoDB') ]] || echo 'MongoDB 27017'
        [[ -z $(sig_list RUNNING '^Memcached') ]] || echo 'Memcached 11211'
        [[ -z $(sig_list RUNNING '^RabbitMQ') ]] || echo 'RabbitMQ 5672'
        [[ -z $(sig_list RUNNING '^ClickHouse') ]] || echo 'ClickHouse 9000'
        [[ -z $(sig_list RUNNING '^Apache Kafka') ]] || echo 'Kafka 9092'
        [[ -z $(sig_list RUNNING '^Apache Cassandra') ]] || echo 'Cassandra 9042'
        [[ -z $(sig_list RUNNING '^InfluxDB') ]] || echo 'InfluxDB 8086'
        [[ -z $(sig_list RUNNING '^NATS') ]] || echo 'NATS 4222'
    )"
    for ((line = 0; line < CT_N; line++)); do
        out=$(printf '%s\n' "${CT_ROWS[line]}" | awk -F '|' 'tolower($2) ~ /(mysql|mariadb|postgres|redis|valkey|mongo|elastic|opensearch|rabbitmq|clickhouse|kafka|cassandra|influxdb)/ {
            printf "%s (%s) ", $1, ($3 ~ /^Up/ ? "up" : "down") }')
        [[ -z $out ]] || db_row 'In containers' "${CT_ENGINE[line]}" "$out"
    done
    return 0
}

view_data() {
    title 'Databases and caches' 'Where apps keep their data. Checked locally, without any password.'
    if [[ -n $DB_ROWS ]]; then
        printf '  %-16s %-14s %s\n' SERVICE STATE DETAIL
        printf '%s' "$DB_ROWS" | clean | indent
    else
        printf '  No database or cache server found.\n'
    fi
    sub 'Problems found here'
    show_findings data
    tips_begin
    tip 'mysql -e "SHOW PROCESSLIST"' 'what MySQL is doing now'
    tip 'mysqladmin status' 'MySQL one-line health'
    tip 'pg_isready' 'does PostgreSQL answer'
    tip 'redis-cli info memory' 'Redis memory use'
    tip 'du -sh /var/lib/mysql /var/lib/postgresql' 'database size on disk'
}

# ---------------------------------------------------------------------------
# Security posture
# ---------------------------------------------------------------------------
# What sshd reads, for when "sshd -T" cannot run. The first value wins, an Include counts where
# it stands, and whatever follows a Match applies to some logins only.
sshd_file_settings() {
    local main=$1 files
    files=$(printf '%s ' "${main%/*}"/sshd_config.d/*.conf)
    awk -v included="$files" '
        function take(file,   line, w, n, i, f) {
            while ((getline line < file) > 0) {
                sub(/^[ \t]+/, "", line)
                if (line == "" || line ~ /^#/) continue
                n = split(line, w, /[ \t=]+/)
                if (n < 2) continue
                w[1] = tolower(w[1])
                if (w[1] == "match") break
                if (w[1] == "include") {
                    n = split(included, f, " ")
                    for (i = 1; i <= n; i++) take(f[i])
                    continue
                }
                if (!(w[1] in seen)) { seen[w[1]] = 1; print w[1], tolower(w[2]) }
            }
            close(file)
        }
        BEGIN { take("'"$main"'") }' 2>/dev/null
}

kernel_newest() { sed 's|.*/vmlinuz-||' | grep '^[0-9]' | grep -v 'rescue\|debug' | sort -V 2>/dev/null | tail -n 1; }

check_security() {
    local out count value pid exe
    S_SSH= S_UPDATES=unknown S_FAILED=
    if has sshd && ((LHA_UID == 0)); then out=$(run_t 5 sshd -T 2>/dev/null); else out=; fi
    if [[ -z $out && -r /etc/ssh/sshd_config ]]; then
        out=$(sshd_file_settings /etc/ssh/sshd_config)
    fi
    if [[ -n $out ]]; then
        value=$(awk '$1 == "permitrootlogin" { print $2 }' <<< "$out")
        count=$(awk '$1 == "passwordauthentication" { print $2 }' <<< "$out")
        S_SSH="root login ${value:-default}, password login ${count:-default}, port $(awk '$1 == "port" { print $2; exit }' <<< "$out")"
        if [[ $value == yes && $count != no ]]; then
            fid=ssh-root-password finding WARN security 'SSH allows root login with a password' \
                'Bots guess root passwords all day. Prefer SSH keys.' 'grep -Ei "permitroot|passwordauth" /etc/ssh/sshd_config'
        fi
    fi
    value=$(awk -F: '$3 == 0 && $1 != "root" { printf "%s%s", (n++ ? ", " : ""), $1 }' /etc/passwd 2>/dev/null | clean)
    if [[ -n $value ]]; then
        fid=extra-uid0 ftarget="$value" finding CRIT security "Account with root power besides root: $value" \
            'If nobody here created it on purpose, treat it as a break-in.' "awk -F: '\$3 == 0' /etc/passwd"
    fi
    if [[ -r /etc/shadow ]]; then
        # Only count. Password hashes must never appear in output.
        count=$(awk -F: '$2 == "" { n++ } END { print n + 0 }' /etc/shadow 2>/dev/null)
        if ((count > 0)); then
            fid=empty-passwords finding CRIT security "$count accounts have an empty password" \
                'Anyone could log in as them without a password.' "sudo awk -F: '\$2 == \"\" { print \$1 }' /etc/shadow"
        fi
    fi
    while read -r pid exe; do
        [[ -n $pid ]] || continue
        fid=exe-in-tmp ftarget="$pid" finding WARN security "A program runs from a temporary folder (PID $pid)" \
            "$(printf '%s' "$exe" | cut -c1-60). Malware likes these folders." "ls -l /proc/$pid/exe"
    done <<< "$(ls -l /proc/[0-9]*/exe 2>/dev/null | clean | awk '
        match($0, / -> \/(tmp|var\/tmp|dev\/shm)\//) {
            link = substr($0, RSTART + 4)
            n = split($(NF - 2), p, "/")
            for (i = 1; i <= NF; i++) if ($i == "->") n = split($(i - 1), p, "/")
            print p[3], link
        }')"
    if [[ -z $H_CONTAINER ]]; then
        # Alpine and Arch name theirs vmlinuz-lts and vmlinuz-linux, which is no version.
        value=$(ls /boot/vmlinuz-* 2>/dev/null | kernel_newest)
        if [[ -n $value && $value != "$H_KERNEL" ]]; then
            fid=kernel-pending ftarget="$value" finding WARN security "A newer kernel is installed: $value" \
                "The server still runs $H_KERNEL, so its fixes are not active until a reboot." 'uname -r'
        fi
    fi
    if [[ -f /var/run/reboot-required ]]; then
        fid=reboot-required finding WARN security 'A reboot is required' 'Installed security fixes are not active until a reboot.' 'cat /var/run/reboot-required.pkgs'
    fi
    if has apt-get; then
        # Empty cache paths keep apt from rewriting its package cache files.
        out=$(run_t 15 apt-get -s -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade 2>/dev/null)
        if (($? == 0)); then
            S_UPDATES=$(grep -c '^Inst ' <<< "$out")
            count=$(grep -c '^Inst .*[Ss]ecurity' <<< "$out")
        fi
    elif has apk; then
        S_UPDATES=$(run_t 10 apk version -l '<' 2>/dev/null | awk 'NR > 1 { n++ } END { print n + 0 }'); count=0
    elif has pacman; then
        S_UPDATES=$(run_t 10 pacman -Qu 2>/dev/null | awk 'END { print NR }'); count=0
    fi
    if [[ $S_UPDATES =~ ^[0-9]+$ ]] && ((S_UPDATES > 0)); then
        if ((${count:-0} > 0)); then
            fid=updates-security finding WARN security "$count security updates are waiting ($S_UPDATES updates in total)" \
                'Known holes stay open until they are installed.' 'apt list --upgradable'
        elif ((S_UPDATES >= 50)); then
            fid=updates-many finding INFO security "$S_UPDATES package updates are waiting" 'The system has not been updated for a while.' 'apt list --upgradable'
        fi
    fi
    # Plain log files first: a time-filtered journal search can take many seconds.
    if [[ -r /var/log/secure ]]; then S_FAILED=$(tail -n 20000 /var/log/secure | grep -c 'Failed password\|Invalid user')
    elif [[ -r /var/log/auth.log ]]; then S_FAILED=$(tail -n 20000 /var/log/auth.log | grep -c 'Failed password\|Invalid user')
    elif has journalctl; then
        S_FAILED=$(run_t 10 journalctl --since '24 hours ago' -t sshd -t sshd-session --no-pager -q 2>/dev/null | grep -c 'Failed password\|Invalid user')
    fi
    return 0
}

view_security() {
    local mode list
    title 'Security' 'Who can get in, what is exposed, and what is unpatched.'
    kv Firewall "$NET_FW"
    kv SSH "${S_SSH:-unknown}"
    kv 'Failed logins' "${S_FAILED:-unknown} in the last day or recent log"
    if [[ $S_UPDATES =~ ^[0-9]+$ ]]; then kv Updates "$S_UPDATES waiting"
    else kv Updates 'not checked here, since dnf and yum write to their logs. Try: dnf check-update'
    fi
    if has getenforce; then mode=SELinux:$(run_t 3 getenforce 2>/dev/null); kv Hardening "$mode"
    elif [[ -r /sys/module/apparmor/parameters/enabled ]]; then kv Hardening "AppArmor: $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)"
    fi
    list=$(sig_list RUNNING . 'Security')
    kv Protection "${list:-no security agent running}"
    if has fail2ban-client; then
        sub 'Fail2ban jails'
        run_t 5 fail2ban-client status 2>/dev/null | clean | indent
    fi
    sub 'Who can log in with a shell'
    awk -F: '$7 !~ /(nologin|noshell|false|sync|shutdown|halt)$/ { printf "  %-20s uid %-6s %s\n", $1, $3, $7 }' /etc/passwd 2>/dev/null | clean | head -n 20
    if has last; then
        sub 'Last logins'
        run_t 5 last -n 6 -w 2>/dev/null | clean | grep -v '^$\|^wtmp' | cut -c1-76 | indent
    fi
    sub 'Problems found here'
    show_findings security
    tips_begin
    tip 'last -n 20' 'recent logins'
    tip 'who' 'who is logged in right now'
    tip 'ss -lntup' 'every open door'
    tip 'ufw status verbose' 'firewall rules on Ubuntu or Debian'
    tip 'firewall-cmd --list-all' 'firewall rules on RHEL family'
    tip 'fail2ban-client status sshd' 'attackers blocked on SSH'
}

# ---------------------------------------------------------------------------
# Logs: what went wrong recently, and why services stopped
# ---------------------------------------------------------------------------
kernel_log() {
    if has journalctl; then run_t 10 journalctl -k --since '7 days ago' --no-pager -q 2>/dev/null
    else run_t 5 dmesg 2>/dev/null
    fi
}

check_logs() {
    local log count
    log=$(kernel_log | clean)
    L_OOM=$(grep -i 'out of memory\|oom-kill\|oom_reaper' <<< "$log" | tail -n 8 | cut -c1-120)
    local victims
    victims=$(grep -io 'killed process [0-9]* ([^)]*)' <<< "$log" | sed 's/.*(//; s/)//' | sort | uniq -c | sort -rn |
        head -n 4 | awk '{ printf "%s%s x%s", (NR > 1 ? ", " : ""), $2, $1 }')
    if [[ ${R_OOM:-0} =~ ^[1-9] || -n $victims ]]; then
        # The journal reaches past the last boot, while the counter starts at zero with each boot.
        if [[ ${R_OOM:-0} =~ ^[1-9] ]]; then count="The kernel killed $R_OOM processes for lack of memory since boot"
        else count='The kernel killed processes for lack of memory in the last 7 days'
        fi
        fid=oom-kills ftarget="$victims" finding WARN resources "$count" \
            "${victims:+Killed in the last 7 days: $victims. }A service may have died silently. Add RAM or lower its memory settings." \
            'journalctl -k | grep -i "out of memory"'
    fi
    # Virtual floppy, CD and loop devices log I/O errors on healthy VMs, and the kernel's
    # boot command line can hold options such as nvme_core.io_timeout.
    count=$(grep -iE 'i/o error|ext4-fs error|xfs.*(corruption|error)|nvme.*(timeout|reset)|ata[0-9]+.*failed|blk_update_request' <<< "$log" |
        grep -ivE 'dev (fd|sr|loop)[0-9]|command line')
    L_DISK=$(tail -n 8 <<< "$count" | cut -c1-120)
    L_HW=$(grep -iE 'machine check events logged|hardware error|soft lockup|blocked for more than|segfault' <<< "$log" |
        grep -iv 'command line' | tail -n 8 | cut -c1-120)
    if [[ -n $L_DISK ]]; then
        fid=disk-errors finding CRIT disk "Kernel logged $(awk 'END { print NR }' <<< "$count") disk errors recently" \
            'The disk may be failing. Check your backups before anything else.' 'journalctl -k -p err --since "7 days ago"'
    fi
    if [[ -n $L_HW ]]; then
        fid=kernel-faults finding WARN host 'Kernel logged crashes or hardware warnings' \
            'Programs crashed, or the hardware reported a fault.' 'journalctl -k -p warning --since "7 days ago"'
    fi
    return 0
}

view_logs() {
    local diagnostic_units journal=yes i line
    title 'Logs and recent trouble' 'Logs are the diary of a server. They explain why something stopped.'
    printf '  %sLog lines can contain private data. Think before sharing this section.%s\n' "$c_dim" "$c_off"
    sub 'Reboots'
    if has last; then run_t 5 last -x -n 5 reboot shutdown 2>/dev/null | clean | grep -v '^$\|^wtmp' | cut -c1-76 | indent
    else printf '  Unavailable\n'; fi
    sub 'Out-of-memory kills'
    if [[ -n $L_OOM ]]; then printf '%s\n' "$L_OOM" | indent; else printf '  None in the visible kernel log.\n'; fi
    sub 'Disk errors'
    if [[ -n $L_DISK ]]; then printf '%s\n' "$L_DISK" | indent; else printf '  None in the visible kernel log.\n'; fi
    sub 'Crashes and hardware warnings'
    if [[ -n $L_HW ]]; then printf '%s\n' "$L_HW" | indent; else printf '  None in the visible kernel log.\n'; fi
    if [[ -n $SVC_FAILED ]]; then
        diagnostic_units=$SVC_FAILED$'\n'
        service_report | clean
    fi
    for ((i = 0; i < CT_N; i++)); do
        [[ ${CT_ENGINE[i]} != crictl ]] || continue
        while IFS='|' read -r line _; do
            [[ -n $line ]] || continue
            sub "Last log lines of container $line"
            run_t 8 "${CT_ENGINE[i]}" logs --tail 8 "$line" 2>&1 | clean | cut -c1-120 | indent
        done <<< "$(printf '%s\n' "${CT_ROWS[i]}" | awk -F '|' '$3 ~ /unhealthy|Restarting/ || ($3 ~ /^Exited/ && $3 !~ /^Exited \((0|143)\)/)' | head -n 5)"
    done
    if has journalctl; then
        sub 'Latest errors from all services'
        run_t 10 journalctl -p err -b -n 15 --no-pager -q -o short-iso 2>/dev/null | clean | cut -c1-120 | indent
        line=$(run_t 5 journalctl --disk-usage 2>/dev/null | clean)
        [[ -z $line ]] || kv 'Journal size' "$line"
    fi
    tips_begin
    tip 'journalctl -u NAME -n 100' 'logs of one service'
    tip 'journalctl -p err -b' 'all errors since the last boot'
    tip 'journalctl -f' 'follow new logs live'
    tip 'dmesg -T | tail -30' 'messages from the kernel'
    tip 'ls -lhS /var/log | head' 'biggest log files'
}

# ---------------------------------------------------------------------------
# Scheduled jobs, backups and monitoring agents
# ---------------------------------------------------------------------------
check_jobs() {
    local cron='' f newest age
    J_BACKUP_AGE=
    J_BACKUP=$(sig_list 'RUNNING|PRESENT' '^(JetBackup|Acronis|Restic|BorgBackup|Duplicity|rclone|Veeam|Bacula|Proxmox Backup)')
    J_MONITOR=$(sig_list 'RUNNING' '^(Prometheus|Grafana|Netdata|Zabbix|Datadog|Telegraf|New Relic|Elastic Agent|Uptime Kuma|Glances|Nagios|Sysdig|Dynatrace)')
    J_TIMERS=
    if [[ $systemd_visible == yes ]]; then
        J_TIMERS=$(run_t 5 systemctl --system list-timers --all --no-legend --no-pager 2>/dev/null | clean)
    fi
    J_CRON=$(cat /etc/crontab /etc/cron.d/* 2>/dev/null | clean | awk '!/^[ \t]*(#|$)/ && !/^[A-Z_]+=/')
    # Read the spool directly: "crontab -l" writes a line to the cron log.
    cron=$(cat "/var/spool/cron/crontabs/${USER:-root}" "/var/spool/cron/${USER:-root}" 2>/dev/null | clean | awk '!/^[ \t]*(#|$)/')
    J_USER_CRON=$cron
    for f in /backup /backups; do
        [[ -d $f ]] || continue
        newest=$(ls -td "$f"/* 2>/dev/null | head -n 1)
        [[ -n $newest ]] || continue
        age=$(stat -c %Y "$newest" 2>/dev/null)
        [[ $age =~ ^[0-9]+$ ]] || continue
        age=$((($(date +%s) - age) / 86400))
        J_BACKUP_AGE="newest in $f is $age days old"
        if ((age > 8)); then
            fid=backup-old ftarget="$f" finding WARN jobs "The newest backup in $f is $age days old" \
                'Backups may have stopped. An old backup means lost work.' "ls -lt $f | head"
        fi
        break
    done
    if [[ -z $J_BACKUP ]] &&
        grep -qiE 'backup|restic|borg|mysqldump|mariadb-dump|pg_dump|rsync|velero' <<< "$J_CRON"$'\n'"$cron"$'\n'"$J_TIMERS"; then
        J_BACKUP='a scheduled job mentions backups; confirm it works'
    fi
    if [[ -z $J_BACKUP ]]; then
        fid=backup-missing finding WARN jobs 'No backup tool or backup job was found' \
            'This check only sees this server. Confirm that a backup exists somewhere and that it restores.' 'crontab -l'
    fi
    if [[ -z $J_MONITOR ]]; then
        fid=monitoring-missing finding INFO jobs 'No monitoring agent is running' \
            'Nothing warns you when this server has a problem. This tool only sees right now.' ''
    fi
    return 0
}

view_jobs() {
    title 'Scheduled jobs, backups and monitoring' 'What runs by itself, and what protects you when things break.'
    kv Backups "${J_BACKUP:-no backup tool seen}"
    [[ -z $J_BACKUP_AGE ]] || kv 'Backup age' "$J_BACKUP_AGE"
    kv Monitoring "${J_MONITOR:-no agent running}"
    if [[ -n $J_USER_CRON ]]; then sub 'Cron jobs of this user'; printf '%s\n' "$J_USER_CRON" | cut -c1-100 | head -n 20 | indent; fi
    if [[ -n $J_CRON ]]; then sub 'System cron jobs'; printf '%s\n' "$J_CRON" | cut -c1-100 | head -n 25 | indent; fi
    if [[ -n $J_TIMERS ]]; then sub 'systemd timers'; printf '%s\n' "$J_TIMERS" | cut -c1-110 | head -n 20 | indent; fi
    sub 'Problems found here'
    show_findings jobs
    tips_begin
    tip 'crontab -l' 'your scheduled jobs'
    tip 'ls /etc/cron.d /etc/cron.daily' 'system scheduled jobs'
    tip 'systemctl list-timers' 'modern scheduled jobs, with next and last run'
}

# ---------------------------------------------------------------------------
# Learn: a short guided tour, fitted to what this server has
# ---------------------------------------------------------------------------
view_learn() {
    title 'Learn your server in 10 steps' 'Run these in order. All are read-only and safe.'
    tip 'hostnamectl' '1. What machine and OS is this?'
    tip 'uptime' '2. How long is it up, how loaded? Load near the CPU count is full.'
    tip 'free -h' '3. Is RAM short? Read "available".'
    tip 'df -h' '4. Is any disk near full?'
    tip 'systemctl --failed' '5. Did anything crash?'
    tip 'ss -lntup' '6. Which programs are open to the network?'
    tip 'top' '7. What is using CPU and RAM right now?'
    tip 'journalctl -p err -b' '8. What errors happened since boot?'
    tip 'last -n 10' '9. Who logged in?'
    tip 'crontab -l' '10. What runs by itself?'
    sub 'Words you will meet'
    cat <<'EOF'
  Service     A program kept running in the background by the system (systemd).
  Process     One running program. A service can have many.
  Port        A numbered door on the network. Each listens for one program.
  Load        Tasks running or waiting. Compare it with the number of CPU cores.
  Available   RAM that can be used now. Linux borrows free RAM as disk cache.
  Swap        Disk used as slow extra RAM. Heavy use means RAM is short.
  Inode       One file slot on a disk. A disk can run out of these too.
  OOM killer  Kernel feature that kills a process when memory runs out.
  Container   An app isolated with its own files, sharing the host kernel.
  Image       The template a container starts from.
  Pod         The Kubernetes unit: one or more containers run together.
  Node        One server in a Kubernetes cluster.
  Reverse     A front server, such as Nginx, passing visitors to apps behind it.
   proxy
  TLS/SSL     The encryption behind https. Certificates expire, so renew them.
EOF
    if ((CT_N > 0)); then
        sub 'This server uses containers'
        tip 'docker ps' 'what is running'
        tip 'docker logs --tail 50 NAME' 'why it misbehaves'
    fi
    if [[ $K_ON == yes ]]; then
        sub 'This server is part of Kubernetes'
        tip 'kubectl get pods -A' 'state of all apps (kubectl keeps a small cache in ~/.kube)'
        tip 'kubectl describe pod NAME -n NS' 'why one is stuck'
    fi
    printf '\n  %sEvery section of this tool ends with its own commands to try.%s\n' "$c_dim" "$c_off"
}

# ---------------------------------------------------------------------------
# Overview: the first screen
# ---------------------------------------------------------------------------
run_checks() {
    [[ ${checks_done:-no} != yes ]] || return 0
    checks_done=yes
    progress 'software and services'
    scan_evidence
    progress 'host'
    check_host
    progress 'CPU, memory and disk'
    check_resources
    progress 'services'
    check_services
    check_mail
    progress 'ports and firewall'
    check_network
    progress 'containers'
    check_containers
    progress 'Kubernetes'
    check_kube
    progress 'websites and certificates'
    check_web
    progress 'databases'
    check_data
    check_app_versions
    progress 'security and updates'
    check_security
    progress 'logs'
    check_logs
    progress 'jobs and backups'
    check_jobs
    progress ''
    if [[ ${tui_active:-no} == yes ]]; then printf '\r\033[K' >&9
    elif [[ -t 2 ]]; then printf '\r\033[K' >&2
    fi
}

verdict() {
    if ((F_CRIT > 0)); then printf '%sNEEDS ATTENTION NOW%s: %d critical, %d warnings' "$c_red$c_bold" "$c_off" "$F_CRIT" "$F_WARN"
    elif ((F_WARN > 0)); then printf '%sWORKING, WITH WARNINGS%s: %d warnings' "$c_yel$c_bold" "$c_off" "$F_WARN"
    else printf '%sHEALTHY%s: no problems found by these checks' "$c_grn$c_bold" "$c_off"
    fi
}

meter() {
    local value=$1 width=24 fill color=$c_grn bar rest
    if ((value < 0)); then printf '%24s  --' ''; return 0; fi
    ((value <= 100)) || value=100
    fill=$((value * width / 100))
    if ((value >= 90)); then color=$c_red; elif ((value >= 75)); then color=$c_yel; fi
    printf -v bar '%*s' "$fill" ''
    printf -v rest '%*s' "$((width - fill))" ''
    printf '%s%s%s%s%s%s %3d%%' "$color" "${bar// /$g_full}" "$c_off" "$c_dim" "${rest// /$g_empty}" "$c_off" "$value"
}

# One glance at every area: icon, then name.
scorecard() {
    local item area name count=0 icon color
    for item in 'resources:CPU and RAM' 'disk:Disks' 'services:Services' 'network:Network' 'security:Security' \
        'containers:Containers' 'kubernetes:Kubernetes' 'web:Websites' 'data:Databases' 'jobs:Backups, jobs'; do
        area=${item%%:*} name=${item#*:}
        case $area in
            containers) ((CT_N > 0)) || continue ;;
            kubernetes) [[ $K_ON == yes ]] || continue ;;
            web) [[ -n $W_DOMAINS || -n $W_CERTS ]] || continue ;;
            data) [[ -n $DB_ROWS ]] || continue ;;
        esac
        menu_state "$area"
        case $REPLY in
            crit) icon=$g_crit color=$c_red ;;
            warn) icon=$g_warn color=$c_yel ;;
            *) icon=$g_ok color=$c_grn ;;
        esac
        printf '  %s%s%s %-13s' "$color" "$icon" "$c_off" "$name"
        ((count += 1))
        ((count % 4)) || printf '\n'
    done
    ((count % 4 == 0)) || printf '\n'
}

role_guess() {
    local -a roles=()
    [[ $K_ON != yes ]] || roles+=("Kubernetes $([[ $K_API == yes ]] && printf cluster || printf node)")
    ((CT_N == 0)) || roles+=('container host')
    [[ -z $CT_PLATFORMS ]] || roles+=('virtualization host')
    [[ -z $(sig_list RUNNING . 'Hosting panels') ]] || roles+=('hosting panel')
    [[ -z $(sig_list RUNNING '^(Nginx|Apache HTTP|LiteSpeed server|OpenLiteSpeed|Caddy|Lighttpd|Apache Tomcat)') ]] || roles+=('web server')
    [[ -z $(sig_list RUNNING '^(HAProxy|Traefik|Envoy)') ]] || roles+=('load balancer')
    [[ -z $DB_ROWS ]] || roles+=('database or cache')
    [[ -z $(sig_list RUNNING '^(Postfix|Exim|Dovecot|Sendmail)') ]] || roles+=('mail server')
    [[ -z $(sig_list RUNNING '^(BIND|PowerDNS auth|Knot|NSD)') ]] || roles+=('DNS server')
    [[ -z $(sig_list RUNNING '^(OpenVPN|WireGuard|Tailscale|ZeroTier)') ]] || roles+=('VPN')
    if ((${#roles[@]} == 0)); then printf 'general server, no main role recognized\n'; return 0; fi
    local IFS=,
    printf '%s\n' "${roles[*]}" | sed 's/,/, /g'
}

view_overview() {
    local mnt use size free group list i line place proto port scope addr proc pid
    printf '%sLINUX SERVER OVERVIEW%s  %s  %s%s%s\n' "$c_bold$c_cyan" "$c_off" "${H_NAME:-unknown}" "$c_dim" "${H_TIME:-}" "$c_off"
    title 'What this server is'
    place=$H_VIRT
    [[ -z $H_PLACE ]] || place+=", $H_PLACE"
    [[ -z $H_CONTAINER ]] || place="inside a $H_CONTAINER container"
    kv System "$H_OS${H_EOL:+, security updates until $H_EOL}"
    kv Kernel "$H_KERNEL ($H_ARCH), started by $H_INIT"
    kv Machine "$place"
    kv Hardware "$H_CPUS CPU cores${H_MODEL:+ ($H_MODEL)}, $(human_kb "$R_MEM_TOTAL") RAM"
    kv Up "$(human_age "$H_UPTIME")"
    kv Address "${H_IP:-unknown}"
    kv Role "$(role_guess)"
    if ((LHA_UID == 0)); then kv Access root; else kv Access 'limited user: run with sudo to see everything'; fi

    title 'Health right now'
    printf '  %s\n\n' "$(verdict)"
    scorecard
    printf '\n'
    printf '  %-14s %s  %s\n' CPU "$(meter "$R_CPU")" "load $R_LOAD1"
    printf '  %-14s %s  %s\n' RAM "$(meter "$R_MEM_PCT")" "$(human_kb "$R_MEM_AVAIL") available"
    if ((R_SWAP_TOTAL > 0)); then
        printf '  %-14s %s\n' Swap "$(meter "$((R_SWAP_USED * 100 / R_SWAP_TOTAL))")"
    fi
    while read -r mnt use size free; do
        [[ -n $mnt ]] || continue
        printf '  %-14.14s %s  %s free\n' "$mnt" "$(meter "$use")" "$(human_kb "$free")"
    done <<< "$(head -n 6 <<< "$R_DISKS")"

    if ((F_CRIT + F_WARN > 0)); then
        title 'What needs your attention'
        show_top_findings 8
    fi

    title 'What is running'
    while IFS= read -r group; do
        [[ -n $group ]] || continue
        list=$(sig_list RUNNING . "$group")
        [[ -z $list ]] || printf '  %-30.30s %s\n' "$group" "$list" | cut -c1-110
    done <<< "$sig_groups"
    for ((i = 0; i < CT_N; i++)); do kv "${CT_ENGINE[i]}" "${CT_STATE[i]}"; done
    if [[ $K_ON == yes ]]; then
        if [[ $K_API == yes ]]; then kv Kubernetes "$K_READY/$K_NODES nodes ready, $K_PODS pods, $K_BAD not healthy"
        else kv Kubernetes "${K_DIST:-found}, cluster state not readable here"
        fi
    fi
    [[ -z $CT_PLATFORMS ]] || kv Virtualization "$CT_PLATFORMS"
    if [[ -n $SVC_APPS ]]; then kv 'Other apps' "$(awk 'NF { n++ } END { print n + 0 }' <<< "$SVC_APPS") application services (see Applications)"; fi
    if [[ -n $W_DOMAINS ]]; then kv Domains "$(awk 'NF { n++ } END { print n + 0 }' <<< "$W_DOMAINS") in web config, $W_CERT_N TLS certificates"; fi
    kv Backups "${J_BACKUP:-none seen}"
    kv Monitoring "${J_MONITOR:-none running}"

    title 'Open to the network' "$NET_PUBLIC public ports of $NET_TOTAL open. Firewall: $NET_FW"
    i=0
    while read -r proto port scope addr proc pid; do
        [[ $scope == public ]] || continue
        port_name "$port"
        ((i += 1))
        ((i <= 12)) || continue
        printf '  %5s/%-4s %-18.18s %s\n' "$port" "$proto" "$proc" "$REPLY"
    done <<< "$NET_ROWS"
    ((i <= 12)) || printf '  and %d more (see Ports and network)\n' "$((i - 12))"
}

view_problems() {
    title 'Problems and what to do' 'Most severe first. "Next" commands only look; they change nothing unless noted.'
    printf '  %s\n\n' "$(verdict)"
    show_findings
    printf '\n  %sThese checks catch common problems. A clean result does not prove the server is secure or bug-free.%s\n' "$c_dim" "$c_off"
}

view_report() {
    view_overview
    view_problems
    view_resources
    view_apps
    view_network
    view_containers
    view_kube
    view_web
    view_data
    view_tune
    view_security
    view_jobs
    view_logs
    print_signatures
    title 'Done' "Read-only scan of ${H_NAME:-this server} finished."
}

# ---------------------------------------------------------------------------
# End of official support for the applications in use
# ---------------------------------------------------------------------------
app_row() {
    local app=$1 version=$2 eol=$3
    [[ -n $eol ]] || return 0
    APP_ROWS+="$app|$version|$eol"$'\n'
    if [[ $eol < $(date +%Y-%m) ]]; then
        fid=app-eol ftarget="$app:$version" finding WARN security "$app $version no longer gets official fixes" \
            "Official support ended in $eol. Your OS vendor may still patch it. Check, then plan an upgrade." \
            "$app --version"
    fi
}

# "mysql  Ver 8.0.36 for Linux", "mysql  Ver 14.14 Distrib 5.7.44" or "mariadb from 11.4.2-MariaDB".
client_version() { sed -E 's/.*(Distrib|Ver|from) ([0-9]+\.[0-9]+).*/\2/'; }

check_app_versions() {
    local text version listed=' ' eol
    APP_ROWS=
    # Every PHP that actually serves sites, plus the command line one.
    text=$(printf '%s' "$active_units" | awk '$3 == "active" && $1 ~ /php/ { print $1 }')
    has php && text+=$'\n'php-cli-$(run_t 4 php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null)
    while IFS= read -r version; do
        version=$(sed -E 's/^php-cli-//; s/^[^0-9]*([0-9])\.?([0-9]).*/\1.\2/' <<< "$version")
        [[ $version =~ ^[0-9]\.[0-9]$ && $listed != *" $version "* ]] || continue
        listed+="$version "
        case $version in
            5.*) eol=2018-12 ;; 7.0) eol=2019-01 ;; 7.1) eol=2019-12 ;; 7.2) eol=2020-11 ;;
            7.3) eol=2021-12 ;; 7.4) eol=2022-11 ;; 8.0) eol=2023-11 ;; 8.1) eol=2025-12 ;;
            8.2) eol=2026-12 ;; 8.3) eol=2027-12 ;; 8.4) eol=2028-12 ;; 8.5) eol=2029-12 ;; *) eol= ;;
        esac
        app_row php "$version" "$eol"
    done <<< "$text"
    text=
    if has mariadb; then text=$(run_t 3 mariadb --version 2>/dev/null)
    elif has mysql; then text=$(run_t 3 mysql --version 2>/dev/null)
    fi
    if [[ -n $(sig_list RUNNING '^(MariaDB server|MySQL-compatible)') ]]; then
        version=$(client_version <<< "$text")
        if [[ $text == *MariaDB* ]]; then
            case $version in
                5.*|10.[0-2]) eol=2022-05 ;; 10.3) eol=2023-05 ;; 10.4) eol=2024-06 ;; 10.5) eol=2025-06 ;;
                10.6) eol=2026-07 ;; 10.11) eol=2028-02 ;; 11.4) eol=2029-05 ;; 11.8) eol=2030-06 ;; *) eol= ;;
            esac
            app_row mariadb "$version" "$eol"
        else
            case $version in
                5.5) eol=2018-12 ;; 5.6) eol=2021-02 ;; 5.7) eol=2023-10 ;; 8.0) eol=2026-04 ;; 8.4) eol=2032-04 ;; *) eol= ;;
            esac
            app_row mysql "$version" "$eol"
        fi
    fi
    if [[ -n $(sig_list RUNNING '^PostgreSQL server') ]] && has psql; then
        version=$(run_t 3 psql --version 2>/dev/null | sed -E 's/.* ([0-9]+)[.0-9]*.*/\1/')
        case $version in
            9|10) eol=2022-11 ;; 11) eol=2023-11 ;; 12) eol=2024-11 ;; 13) eol=2025-11 ;; 14) eol=2026-11 ;;
            15) eol=2027-11 ;; 16) eol=2028-11 ;; 17) eol=2029-11 ;; 18) eol=2030-11 ;; *) eol= ;;
        esac
        app_row postgresql "$version" "$eol"
    fi
    if has node; then
        version=$(run_t 3 node --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/')
        if [[ $version =~ ^[0-9]+$ ]]; then
            case $version in
                ?|1[0-6]) eol=2023-09 ;; 17|18) eol=2025-04 ;; 19|20) eol=2026-04 ;; 21|22) eol=2027-04 ;;
                23|24) eol=2028-04 ;; 25|26) eol=2029-04 ;; *) eol= ;;
            esac
            app_row nodejs "$version" "$eol"
        fi
    fi
    return 0
}

# ---------------------------------------------------------------------------
# JSON: everything a script or a future fixer needs, with no English to parse
# ---------------------------------------------------------------------------
js() {
    local text=$1
    text=${text//\\/\\\\}
    text=${text//\"/\\\"}
    text=${text//$'\t'/ }
    text=${text//$'\n'/ }
    text=${text//$'\r'/ }
    printf '"%s"' "$text"
}

view_json() {
    local i sep='' proto port scope addr proc pid line group label status
    printf '{"tool":"linux-host-audit","version":%s,"generated":%s,' "$(js "$LHA_VERSION")" "$(js "$(date -u '+%Y-%m-%dT%H:%M:%SZ')")"
    printf '"host":{"name":%s,"os_id":%s,"os_version":%s,"os":%s,"os_eol":%s,' "$(js "$H_NAME")" "$(js "$H_OS_ID")" \
        "$(js "$H_OS_VERSION")" "$(js "$H_OS")" "$(js "$H_EOL")"
    printf '"kernel":%s,"arch":%s,"init":%s,"package_manager":%s,"virtualization":%s,"container":%s,' "$(js "$H_KERNEL")" \
        "$(js "$H_ARCH")" "$(js "$H_INIT")" "$(js "$H_PKG")" "$(js "$H_VIRT")" "$(js "$H_CONTAINER")"
    if ((LHA_UID == 0)); then line=true; else line=false; fi
    printf '"cpus":%s,"memory_kb":%s,"uptime_seconds":%s,"is_root":%s},' "$H_CPUS" "${R_MEM_TOTAL:-0}" "${H_UPTIME:-0}" "$line"
    printf '"summary":{"critical":%s,"warning":%s,"info":%s},"findings":[' "$F_CRIT" "$F_WARN" "$F_INFO"
    for ((i = 0; i < F_N; i++)); do
        printf '%s{"id":%s,"severity":%s,"area":%s,"target":%s,"title":%s,"why":%s,"next":%s}' "$sep" "$(js "${F_ID[i]}")" \
            "$(js "${F_SEV[i]}")" "$(js "${F_AREA[i]}")" "$(js "${F_TARGET[i]}")" "$(js "${F_TITLE[i]}")" \
            "$(js "${F_WHY[i]}")" "$(js "${F_NEXT[i]}")"
        sep=,
    done
    printf '],"listeners":['
    sep=
    while read -r proto port scope addr proc pid; do
        [[ -n $proto ]] || continue
        printf '%s{"proto":%s,"port":%s,"scope":%s,"address":%s,"process":%s}' "$sep" "$(js "$proto")" "$port" "$(js "$scope")" \
            "$(js "$addr")" "$(js "$proc")"
        sep=,
    done <<< "$NET_ROWS"
    printf '],"failed_services":['
    sep=
    while read -r line; do
        [[ -n $line ]] || continue
        printf '%s%s' "$sep" "$(js "$line")"
        sep=,
    done <<< "$SVC_FAILED"
    printf '],"app_versions":['
    sep=
    while IFS='|' read -r label line status; do
        [[ -n $label ]] || continue
        printf '%s{"app":%s,"version":%s,"support_until":%s}' "$sep" "$(js "$label")" "$(js "$line")" "$(js "$status")"
        sep=,
    done <<< "$APP_ROWS"
    printf '],"software":['
    sep=
    while IFS='|' read -r group label status line; do
        [[ -n $label && $status != NOT-DETECTED ]] || continue
        printf '%s{"name":%s,"group":%s,"status":%s}' "$sep" "$(js "$label")" "$(js "$group")" "$(js "$status")"
        sep=,
    done <<< "$sig_rows"
    printf ']}\n'
}

# ---------------------------------------------------------------------------
# Tuning and capacity: what each limit is, how full it is, and what real load asks for.
# Read-only. Recommendations come from the service's own counters, never from a size table,
# and a young service gets none: a restart leaves its counters too thin to judge.
# ---------------------------------------------------------------------------
TUNE_MATURE=${LHA_TUNE_MATURE:-86400}

# group|setting|now|used|percent full|recommended|why|how to apply
tune_row() { TUNE_ROWS+="$1|$2|$3|$4|$5|$6|$7|${8:-}|${9:-$6}"$'\n'; }
tune_note() { TUNE_NOTES+="$1|$2"$'\n'; }
tune_budget() { TUNE_BUDGET+="$1|$2"$'\n'; }
tune_get() { awk -F '\t' -v k="$2" '$1 == k { print $2; found = 1; exit } END { if (!found) print 0 }' <<< "$1"; }
tune_size() { human_kb "$((${1:-0} / 1024))"; }
tune_pct() { if ((${2:-0} > 0)); then printf '%d' "$((${1:-0} * 100 / $2))"; else printf 0; fi; }

# Real memory of a few processes, in KiB. RSS counts shared pages once per process, which
# overstates forked workers badly, so use PSS and fall back to RSS on old kernels.
tune_real_kb() {
    local pid sum=0 count=0 value
    for pid in "$@"; do
        value=$(awk '/^Pss:/ { print $2; exit }' "/proc/$pid/smaps_rollup" 2>/dev/null)
        [[ -n $value ]] || value=$(awk '/^VmRSS:/ { print $2; exit }' "/proc/$pid/status" 2>/dev/null)
        [[ $value =~ ^[0-9]+$ ]] || continue
        ((sum += value))
        ((count += 1))
    done
    if ((count > 0)); then printf '%d' "$((sum / count))"; else printf 0; fi
}
tune_round() { local unit=134217728; printf '%d' "$((($1 + unit - 1) / unit * unit))"; }

# Seconds since the oldest process of these names started. Without etimes the answer is 0,
# which counts as young, so such a system gets numbers and no advice.
tune_age() {
    ps -eo etimes=,comm= 2>/dev/null | awk -v names=" $* " '
        index(names, " " $2 " ") && $1 + 0 > m { m = $1 + 0 } END { printf "%d", m }'
}
tune_age_pid() { ps -o etimes= -p "$1" 2>/dev/null | awk 'NR == 1 { printf "%d", $1 }'; }

# True, and says so, while a service is too young to judge.
tune_too_young() {
    ((${2:-0} < TUNE_MATURE)) || return 1
    tune_note "$1" "Running for only $(human_age "${2:-0}"). Numbers are shown, but no advice until it has a full day of traffic."
}

tune_mysql() {
    local client=mysql vars status label version group mature=no
    local max used pool total free fill reads reqs hit up rate data rec why eff tmp disk size files opened now conn created
    [[ -n $(sig_list RUNNING '^(MariaDB server|MySQL-compatible)') ]] || return 0
    has mysql || client=mariadb
    has "$client" || return 0
    vars=$(run_t 8 "$client" --connect-timeout=3 -NBe 'SHOW GLOBAL VARIABLES' 2>/dev/null)
    status=$(run_t 8 "$client" --connect-timeout=3 -NBe 'SHOW GLOBAL STATUS' 2>/dev/null)
    if [[ -z $vars || -z $status ]]; then
        tune_note MySQL 'It needs a password here, so its limits could not be read.'
        return 0
    fi
    version=$(tune_get "$vars" version)
    label=MySQL
    [[ $version != *MariaDB* ]] || label=MariaDB
    group="$label ${version%%-*}"
    up=$(tune_get "$status" Uptime)
    ((up < TUNE_MATURE)) || mature=yes
    tune_too_young "$group" "$up"

    max=$(tune_get "$vars" max_connections)
    used=$(tune_get "$status" Max_used_connections)
    now=$(tune_get "$status" Threads_connected)
    rec='' why=''
    if [[ $mature == yes ]] && ((max > 0)); then
        if (($(tune_get "$status" Connection_errors_max_connections) > 0)) || ((used * 100 / max >= 85)); then
            rec=$((used * 130 / 100 + 10)) why="Peak was $used of $max, so clients are close to being refused."
        elif ((max > 200 && used * 100 / max <= 20)); then
            rec=$((used * 2 > 100 ? used * 2 : 100)) why="Peak was only $used. A high limit reserves no memory, but allows a memory spike."
        fi
    fi
    tune_row "$group" max_connections "$max" "$now now, peak $used" "$(tune_pct "$used" "$max")" "$rec" "$why" 'live'

    pool=$(tune_get "$vars" innodb_buffer_pool_size)
    total=$(tune_get "$status" Innodb_buffer_pool_pages_total)
    free=$(tune_get "$status" Innodb_buffer_pool_pages_free)
    reads=$(tune_get "$status" Innodb_buffer_pool_reads)
    reqs=$(tune_get "$status" Innodb_buffer_pool_read_requests)
    fill=$(tune_pct "$((total - free))" "$total")
    hit=$(awk -v r="$reads" -v q="$reqs" 'BEGIN { if (q > 0) printf "%.2f", 100 - 100 * r / q; else print "0" }')
    rec='' why=''
    if [[ $mature == yes ]] && ((total > 0)); then
        if ((fill >= 95)) && [[ $(awk -v h="$hit" 'BEGIN { print (h < 99) }') == 1 ]]; then
            rec=$((pool * 3 / 2))
            ((rec <= R_MEM_TOTAL * 512)) || rec=$((R_MEM_TOTAL * 512))
            rec=$(tune_round "$rec")
            if ((rec > pool)); then why="Pool is full and only $hit% of reads come from memory."; else rec=''; fi
        elif ((fill <= 50 && pool > 1073741824)); then
            # Page size first: pages times pool size overflows on a very large pool.
            rec=$(tune_round "$(((total - free) * (pool / total) * 13 / 10))")
            why="Only $fill% is used after $(human_age "$up"). The rest could serve other programs."
        fi
    fi
    tune_row "$group" innodb_buffer_pool_size "$(tune_size "$pool")" "$fill% full, $hit% read hits" "$fill" "${rec:+$(tune_size "$rec")}" "$why" 'live' "$rec"

    tmp=$(tune_get "$status" Created_tmp_tables)
    disk=$(tune_get "$status" Created_tmp_disk_tables)
    eff=$(tune_get "$vars" tmp_table_size)
    size=$(tune_get "$vars" max_heap_table_size)
    ((size >= eff)) || eff=$size
    rec='' why=''
    if [[ $mature == yes ]] && ((tmp > 1000 && disk * 100 / tmp >= 25 && eff < 268435456)); then
        rec=$((eff * 2 > 268435456 ? 268435456 : eff * 2))
        why="$(tune_pct "$disk" "$tmp")% of temporary tables spill to disk. Also check missing indexes. Set max_heap_table_size to match."
    fi
    tune_row "$group" tmp_table_size "$(tune_size "$eff")" "$(tune_pct "$disk" "$tmp")% went to disk" "$(tune_pct "$disk" "$tmp")" "${rec:+$(tune_size "$rec")}" "$why" 'live' "$rec"

    size=$(tune_get "$vars" table_open_cache)
    now=$(tune_get "$status" Open_tables)
    opened=$(tune_get "$status" Opened_tables)
    rec='' why=''
    if [[ $mature == yes ]] && ((up > 0 && size > 0 && now * 100 / size >= 95 && opened / up >= 1)); then
        rec=$((size * 3 / 2)) why="Cache is full, and tables are reopened $((opened / up)) times a second."
    fi
    tune_row "$group" table_open_cache "$size" "$now open" "$(tune_pct "$now" "$size")" "$rec" "$why" 'live'

    size=$(tune_get "$vars" thread_cache_size)
    created=$(tune_get "$status" Threads_created)
    conn=$(tune_get "$status" Connections)
    rec='' why=''
    if [[ $mature == yes ]] && ((conn > 1000 && created * 100 / conn >= 10)); then
        rec=$((size * 2 > 16 ? size * 2 : 16)) ; ((rec <= 100)) || rec=100
        why="$(tune_pct "$created" "$conn")% of connections had to create a new thread."
    fi
    tune_row "$group" thread_cache_size "$size" "$created created" "$(tune_pct "$created" "$conn")" "$rec" "$why" 'live'

    if [[ $mature == yes && $(tune_get "$vars" query_cache_type) == ON ]] && (($(tune_get "$vars" query_cache_size) > 0)); then
        tune_row "$group" query_cache_type ON 'in use' 0 OFF 'It takes a global lock on every write, and slows busy servers. Vendors advise against it.' 'live'
    fi

    size=$(tune_get "$vars" innodb_log_file_size)
    files=$(tune_get "$vars" innodb_log_files_in_group)
    ((files > 0)) || files=1
    local log_name=innodb_log_file_size capacity
    capacity=$(tune_get "$vars" innodb_redo_log_capacity)
    if ((capacity > 0)); then log_name=innodb_redo_log_capacity size=$capacity files=1; fi
    rate=0
    ((up == 0)) || rate=$(($(tune_get "$status" Innodb_os_log_written) * 3600 / up))
    rec='' why=''
    if [[ $mature == yes ]] && ((rate > size * files)); then
        # innodb_log_file_size is per file, so the hour of writes is shared between the files.
        rec=$(tune_round "$(((rate > 4294967296 ? 4294967296 : rate) / files))")
        why="$(tune_size "$rate") of redo log is written each hour. Too small a log causes write stalls."
    fi
    if ((size > 0)); then
        tune_row "$group" "$log_name" "$(tune_size "$size")" "$(tune_size "$rate") per hour" "$(tune_pct "$rate" "$((size * files))")" "${rec:+$(tune_size "$rec")}" "$why" 'restart' "$rec"
    fi

    now=$(tune_get "$status" Slow_queries)
    if ((up > 0)); then
        tune_note "$group" "$(($(tune_get "$status" Questions) / up)) queries a second on average, $now slow queries in $(human_age "$up")."
    fi
    tune_budget "$label" "$((pool + $(tune_get "$vars" key_buffer_size) + max * ($(tune_get "$vars" sort_buffer_size) + $(tune_get "$vars" join_buffer_size) + $(tune_get "$vars" read_buffer_size) + $(tune_get "$vars" read_rnd_buffer_size) + $(tune_get "$vars" thread_stack))))"
}

tune_postgres() {
    local out group max now shared hit rec why ram=$((R_MEM_TOTAL * 1024)) temp work
    [[ -n $(sig_list RUNNING '^PostgreSQL server') ]] || return 0
    # setpriv changes user with no login session, so nothing lands in the auth log.
    if ((LHA_UID != 0)) || ! has setpriv || ! has psql; then
        tune_note PostgreSQL 'Details need root and the setpriv tool.'
        return 0
    fi
    # -X: a .psqlrc can add lines to the output, or run anything.
    out=$(run_t 8 setpriv --reuid=postgres --regid=postgres --clear-groups psql -X -w -AtF $'\t' -c "
        select name, setting from pg_settings where name in ('max_connections','shared_buffers','effective_cache_size','work_mem','server_version_num','block_size')
        union all select 'backends', sum(numbackends)::text from pg_stat_database
        union all select 'hit', round(100.0 * sum(blks_hit) / nullif(sum(blks_hit + blks_read), 0), 2)::text from pg_stat_database
        union all select 'temp_files', sum(temp_files)::text from pg_stat_database
        union all select 'uptime', extract(epoch from now() - pg_postmaster_start_time())::bigint::text" 2>/dev/null)
    if [[ -z $out ]]; then tune_note PostgreSQL 'Its limits could not be read.'; return 0; fi
    group="PostgreSQL $(($(tune_get "$out" server_version_num) / 10000))"
    max=$(tune_get "$out" max_connections)
    now=$(tune_get "$out" backends)
    shared=$(($(tune_get "$out" shared_buffers) * $(tune_get "$out" block_size)))
    hit=$(tune_get "$out" hit)
    rec='' why=''
    if (($(tune_get "$out" uptime) >= TUNE_MATURE)); then
        if ((max > 0 && now * 100 / max >= 85)); then rec=$((max * 3 / 2)) why='Near the limit. A pooler such as PgBouncer is usually better than a higher number.'; fi
    else
        tune_note "$group" 'Running for less than a day, so no advice yet.'
    fi
    tune_row "$group" max_connections "$max" "$now now" "$(tune_pct "$now" "$max")" "$rec" "$why" 'restart'
    rec='' why=''
    if (($(tune_get "$out" uptime) >= TUNE_MATURE)) && [[ -n $hit ]] && [[ $(awk -v h="$hit" 'BEGIN { print (h + 0 < 99) }') == 1 ]] && ((shared < ram / 4)); then
        rec=$(tune_round "$((ram / 4))") why="Only $hit% of reads come from memory, and the buffer is under a quarter of RAM."
    fi
    tune_row "$group" shared_buffers "$(tune_size "$shared")" "$hit% read hits" "$(tune_pct "$shared" "$ram")" "${rec:+$(tune_size "$rec")}" "$why" 'restart'
    work=$(($(tune_get "$out" work_mem) * 1024))
    temp=$(tune_get "$out" temp_files)
    tune_row "$group" work_mem "$(tune_size "$work")" "$temp temp files so far" 0 '' ''
    tune_budget PostgreSQL "$((shared + max * work))"
}

tune_redis() {
    local name=$1 cli=$2 info conf max used clients limit evicted hits misses frag rec why group version port up ram=$((R_MEM_TOTAL * 1024))
    has "$cli" || return 0
    port=$(port_of "${cli%-cli}-server")
    port=${port:-6379}
    info=$(run_t 5 "$cli" -h 127.0.0.1 -p "$port" info 2>/dev/null | tr -d '\r' | tr ':' '\t')
    if [[ -z $info || $info == *NOAUTH* ]]; then tune_note "$name" 'It needs a password, so its limits could not be read.'; return 0; fi
    # Valkey keeps a redis_version of 7.2 for clients, and has its own real version.
    version=$(tune_get "$info" valkey_version)
    [[ $version != 0 ]] || version=$(tune_get "$info" redis_version)
    group="$name $version"
    max=$(tune_get "$info" maxmemory)
    used=$(tune_get "$info" used_memory)
    evicted=$(tune_get "$info" evicted_keys)
    hits=$(tune_get "$info" keyspace_hits)
    misses=$(tune_get "$info" keyspace_misses)
    frag=$(tune_get "$info" mem_fragmentation_ratio)
    up=$(tune_get "$info" uptime_in_seconds)
    tune_too_young "$group" "$up"
    rec='' why=''
    if ((up >= TUNE_MATURE)); then
        if ((max == 0)); then
            # A small instance is no evidence of anything, and a limit fails writes once reached.
            if ((used * 10 >= ram)); then
                rec=$(tune_round "$((used * 2))")
                why='No limit is set, and it already uses a real part of RAM. It can grow until the kernel kills something. Also pick a maxmemory-policy.'
            fi
        elif ((used * 100 / max >= 90 && evicted > 0)); then
            rec=$(tune_round "$((max * 3 / 2))") why="It is full, and has evicted $evicted keys."
        fi
        if [[ -n $rec ]] && ((rec > ram * 3 / 4)); then rec='' why=''; fi
    fi
    tune_row "$group" maxmemory "$( ((max == 0)) && printf unlimited || tune_size "$max")" "$(tune_size "$used") used" "$(tune_pct "$used" "$max")" "${rec:+$(tune_size "$rec")}" "$why" 'live' "$rec"
    conf=$(run_t 5 "$cli" -h 127.0.0.1 -p "$port" config get maxclients 2>/dev/null | tail -n 1 | tr -d '\r')
    clients=$(tune_get "$info" connected_clients)
    if [[ $conf =~ ^[0-9]+$ ]]; then tune_row "$group" maxclients "$conf" "$clients now" "$(tune_pct "$clients" "$conf")" '' ''; fi
    tune_note "$group" "$(tune_pct "$hits" "$((hits + misses))")% cache hit rate, $evicted keys evicted, memory fragmentation $frag."
    if ((max > 0)); then tune_budget "$name" "$max"; else tune_budget "$name" "$used"; fi
}

tune_memcached() {
    local stats max used conn
    [[ -n $(sig_list RUNNING '^Memcached') ]] && has nc || return 0
    stats=$(printf 'stats\r\nquit\r\n' | timeout 3 nc -w 2 127.0.0.1 11211 2>/dev/null | tr -d '\r' | awk '{ print $2 "\t" $3 }')
    [[ -n $stats ]] || return 0
    max=$(tune_get "$stats" limit_maxbytes)
    used=$(tune_get "$stats" bytes)
    conn=$(tune_get "$stats" curr_connections)
    tune_row "Memcached $(tune_get "$stats" version)" memory "$(tune_size "$max")" "$(tune_size "$used") used, $(tune_get "$stats" evictions) evicted" "$(tune_pct "$used" "$max")" '' ''
    tune_row "Memcached $(tune_get "$stats" version)" connections "$(tune_get "$stats" max_connections)" "$conn now" "$(tune_pct "$conn" "$(tune_get "$stats" max_connections)")" '' ''
    tune_budget Memcached "$max"
}

# Established clients on a port list, using only the kernel's own table.
tune_connections() { tcp_count 01 0 65535 "$@"; }

tune_nginx() {
    local conf=/etc/nginx/nginx.conf procs conns cap wp wc rec why group nofile pid busy age
    [[ -n $(sig_list RUNNING '^(Nginx|OpenResty|Tengine)') ]] && has nginx || return 0
    [[ -r $conf ]] || conf=/usr/local/nginx/conf/nginx.conf
    [[ -r $conf ]] || return 0
    group="Nginx $(run_t 3 nginx -v 2>&1 | sed 's/.*nginx\///; s/ .*//')"
    wp=$(awk '!/^[ \t]*#/ && $1 == "worker_processes" { gsub(/;/, "", $2); print $2; exit }' "$conf")
    wc=$(awk '!/^[ \t]*#/ && $1 == "worker_connections" { gsub(/;/, "", $2); print $2; exit }' "$conf")
    wc=${wc:-512}
    procs=$(ps -eo args= 2>/dev/null | grep -c '^nginx: worker process')
    rec='' why=''
    busy=$(ps -eo pcpu=,args= 2>/dev/null | awk '$2 == "nginx:" && $3 == "worker" { s += $1 } END { printf "%d", s }')
    # More workers only help if the ones it has are really busy.
    age=$(tune_age nginx)
    tune_too_young "$group" "$age"
    if [[ $wp =~ ^[0-9]+$ ]] && ((age >= TUNE_MATURE && wp < H_CPUS && procs > 0 && busy / procs >= 50)); then
        rec=auto why="Workers average $((busy / procs))% CPU, and there are $H_CPUS cores."
    fi
    tune_row "$group" worker_processes "${wp:-1}" "$procs running" "$(tune_pct "$procs" "$H_CPUS")" "$rec" "$why" 'reload'
    conns=$(tune_connections 80 443)
    cap=$((procs * wc))
    rec='' why=''
    if ((age >= TUNE_MATURE && cap > 0 && conns * 100 / cap >= 60)); then
        rec=$((wc * 2)) why="$conns open connections of $cap possible. A proxied request uses two."
    fi
    tune_row "$group" worker_connections "$wc" "$conns connections now" "$(tune_pct "$conns" "$cap")" "$rec" "$why" 'reload'
    # Workers carry worker_rlimit_nofile. The master keeps the limit it started with.
    pid=$(ps -eo pid=,args= 2>/dev/null | awk '$2 == "nginx:" && $3 == "worker" { print $1; exit }')
    if [[ $pid =~ ^[0-9]+$ ]]; then
        nofile=$(awk '/^Max open files/ { print $4 }' "/proc/$pid/limits" 2>/dev/null)
        if [[ $nofile =~ ^[0-9]+$ ]] && ((age >= TUNE_MATURE && nofile < wc * 2)); then
            tune_row "$group" worker_rlimit_nofile "$nofile" 'open file limit' 0 "$((wc * 2))" 'Each connection needs a file handle, and a proxied one needs two.' 'reload'
        fi
    fi
}

tune_apache() {
    local bin mpm max threads procs conns reached file rec why group logs=0 real age
    [[ -n $(sig_list RUNNING '^Apache HTTP') ]] || return 0
    if has httpd; then bin=httpd; else bin=apache2; fi
    has "$bin" || return 0
    group="Apache $(run_t 3 "$bin" -v 2>/dev/null | sed -n 's/.*Apache\/\([0-9.]*\).*/\1/p')"
    mpm=$(run_t 3 "$bin" -V 2>/dev/null | awk -F ': *' '/Server MPM/ { print tolower($2) }')
    local R=$LHA_ROOT
    max=$(cat "$R"/etc/apache2/conf/httpd.conf "$R"/etc/apache2/conf.d/*.conf "$R"/etc/httpd/conf/httpd.conf "$R"/etc/httpd/conf.modules.d/*.conf \
        "$R"/etc/apache2/mods-enabled/mpm_*.conf 2>/dev/null | awk 'tolower($1) ~ /^(maxrequestworkers|maxclients)$/ { v = $2 } END { print v }')
    threads=$(cat "$R"/etc/apache2/conf/httpd.conf "$R"/etc/httpd/conf/httpd.conf "$R"/etc/apache2/mods-enabled/mpm_*.conf 2>/dev/null |
        awk 'tolower($1) == "threadsperchild" { v = $2 } END { print v }')
    # A value can be a ${VARIABLE} from the environment file, and only numbers can be computed.
    [[ $threads =~ ^[1-9][0-9]*$ ]] || threads=25
    [[ $max =~ ^[1-9][0-9]*$ ]] || max=
    if [[ -z $max ]]; then
        if [[ $mpm == prefork ]]; then max=256; else max=400; fi
        tune_note "$group" "MaxRequestWorkers is not set, so the $mpm default of $max applies."
    fi
    procs=$(ps -eo comm= 2>/dev/null | grep -cE '^(httpd|apache2)$')
    for file in /var/log/apache2/error.log /var/log/httpd/error_log /etc/apache2/logs/error_log /usr/local/apache/logs/error_log; do
        [[ -r $file ]] || continue
        logs=1
        reached=$(tail -n 50000 "$file" | grep -c 'reached MaxRequestWorkers\|reached MaxClients')
        break
    done
    rec='' why=''
    age=$(tune_age httpd apache2)
    tune_too_young "$group" "$age"
    if ((age >= TUNE_MATURE && ${reached:-0} > 0)); then
        rec=$((max * 3 / 2)) why="The error log shows the limit was hit $reached times, so visitors waited."
    fi
    if [[ $mpm == prefork ]]; then
        tune_row "$group ($mpm)" MaxRequestWorkers "$max" "$((procs > 0 ? procs - 1 : 0)) workers now" "$(tune_pct "$((procs > 0 ? procs - 1 : 0))" "$max")" "$rec" "$why" 'reload'
    else
        tune_row "$group (${mpm:-unknown})" MaxRequestWorkers "$max" "$procs processes, $threads threads each" "$(tune_pct "$((procs * threads))" "$max")" "$rec" "$why" 'reload'
    fi
    ((logs == 1)) || tune_note "$group" 'Its error log was not found, so limit hits could not be counted.'
    # shellcheck disable=SC2046 # pids are split on purpose
    real=$(tune_real_kb $(ps -eo pid=,comm= 2>/dev/null | awk '$2 == "httpd" || $2 == "apache2" { print $1 }' | tail -n 5))
    if [[ $mpm == prefork ]]; then tune_budget Apache "$((real * 1024 * max))"
    else tune_budget Apache "$((real * 1024 * (max / threads + 1)))"
    fi
}

# PHP-FPM is judged per pool, from each pool's file, its workers, and its own limit-hit lines.
tune_phpfpm() {
    local pools workers logs line pool pm max count rss reached rec why total_run=0 shown=0 avg file real budget=0 measured=' ' pids age
    [[ -n $(sig_list RUNNING '^PHP-FPM') ]] || return 0
    # Debian builds name the process after the binary, such as php-fpm8.2: pool www.
    workers=$(ps -eo pid=,rss=,args= 2>/dev/null | awk '$3 ~ /^php-fpm[0-9.]*:$/ && $4 == "pool" { print }')
    age=$(tune_age php-fpm php-fpm5.6 php-fpm7.0 php-fpm7.1 php-fpm7.2 php-fpm7.3 php-fpm7.4 php-fpm8.0 php-fpm8.1 php-fpm8.2 php-fpm8.3 php-fpm8.4 php-fpm8.5)
    tune_too_young 'PHP-FPM pools' "$age"
    pools=$(cat /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf \
        /opt/plesk/php/*/etc/php-fpm.d/*.conf /www/server/php/*/etc/php-fpm.conf 2>/dev/null | clean | awk '
        /^[ \t]*\[.*\]/ { name = $0; gsub(/[][ \t]/, "", name); if (name != "global") seen[name] = 1; next }
        /^[ \t]*pm[ \t]*=/ { pm[name] = $NF }
        /^[ \t]*pm\.max_children[ \t]*=/ { max[name] = $NF }
        # A pool can continue in a later file, so its settings are gathered by name.
        END { for (p in seen) print p, (p in pm ? pm[p] : "?"), (p in max ? max[p] : 0) }')
    for file in /var/log/php-fpm/*.log /var/log/php*-fpm.log /opt/cpanel/ea-php*/root/usr/var/log/php-fpm.log; do
        [[ -r $file ]] && logs+=$(tail -n 20000 "$file" | grep 'reached pm.max_children\|max_children setting')$'\n'
    done
    while read -r count rss pool; do
        [[ -n $pool ]] || continue
        line=$(awk -v p="$pool" '$1 == p { print $2, $3; exit }' <<< "$pools")
        pm=${line%% *} max=${line##* }
        [[ $max =~ ^[0-9]+$ ]] || max=0
        pids=$(awk -v p="$pool" '$5 == p { print $1 }' <<< "$workers" | head -n 4)
        # shellcheck disable=SC2086 # pids are split on purpose
        real=$(tune_real_kb $pids)
        ((real > 0)) || real=$rss
        rss=$real
        ((budget += max * rss * 1024))
        ((total_run += count))
        measured+="$pool "
        ((shown < 8)) || continue
        ((shown += 1))
        reached=$(grep -cF "[pool $pool]" <<< "$logs")
        rec='' why=''
        if ((age >= TUNE_MATURE && reached > 0 && max > 0)); then
            rec=$((max * 3 / 2))
            why="Its log shows the limit was hit $reached times. Each worker uses about $(human_kb "$rss")."
        fi
        tune_row 'PHP-FPM pools' "${pool:0:30} ($pm)" "$max" "$count workers, $(human_kb "$rss") each" "$(tune_pct "$count" "$max")" "$rec" "$why" 'reload'
        if [[ -z $rec ]] && ((age >= TUNE_MATURE && max > 0 && count * 100 / max >= 90)); then
            tune_note 'PHP-FPM pools' "$pool is close to its limit, with no limit hits logged yet. Watch it at peak traffic."
        fi
    done <<< "$(awk '{ n[$5]++; m[$5] += $2 } END { for (p in n) print n[p], int(m[p] / n[p]), p }' <<< "$workers" | sort -rn)"
    # Idle ondemand pools have no worker to measure, so they count at the average of the busy ones.
    avg=0
    ((total_run == 0)) || avg=$(awk '{ s += $2; n++ } END { if (n) printf "%d", s / n }' <<< "$workers")
    while read -r pool pm max; do
        [[ -n $pool && $max =~ ^[0-9]+$ && $measured != *" $pool "* ]] || continue
        ((budget += max * avg * 1024))
    done <<< "$pools"
    ((budget == 0)) || tune_budget 'PHP-FPM' "$budget"
    if [[ -z $pools ]] && ((total_run > 0)); then tune_note 'PHP-FPM pools' 'Pool limits were not found in the usual folders.'; fi
}

tune_elastic() {
    local name=$1 row heap_pct heap_max ram_max disk rec why ver group up
    [[ -n $(sig_list RUNNING "^$name") ]] && has curl || return 0
    ver=$(run_t 5 curl -s -m 3 http://127.0.0.1:9200/ 2>/dev/null | clean | sed -n 's/.*"number" *: *"\([0-9.]*\)".*/\1/p' | head -n 1)
    if [[ -z $ver ]]; then tune_note "$name" 'It needs a password, so its limits could not be read.'; return 0; fi
    group="$name $ver"
    up=$(run_t 5 curl -s -m 3 'http://127.0.0.1:9200/_nodes/stats/jvm?filter_path=nodes.*.jvm.uptime_in_millis' 2>/dev/null | clean |
        sed -n 's/.*"uptime_in_millis" *: *\([0-9]*\).*/\1/p' | head -n 1)
    up=$((${up:-0} / 1000))
    tune_too_young "$group" "$up"
    while read -r row heap_pct heap_max ram_max disk; do
        [[ $heap_max =~ ^[0-9]+$ ]] || continue
        rec='' why=''
        if ((up < TUNE_MATURE)); then :
        elif ((heap_max > 33285996544)); then rec=31g why='Above about 31 GiB, the JVM loses compressed pointers and gets less usable heap.'
        elif ((heap_max * 2 > ram_max + ram_max / 10)); then rec=$(tune_size "$((ram_max / 2))") why='Heap should leave half of RAM to the file cache.'
        elif ((heap_pct >= 85)); then rec=$(tune_size "$((heap_max * 3 / 2))") why="Heap is $heap_pct% full, so long garbage collection pauses are likely."
        fi
        tune_row "$group" "heap $row" "$(tune_size "$heap_max")" "$heap_pct% used" "$heap_pct" "$rec" "$why" 'restart'
        tune_row "$group" "disk $row" "$disk%" 'watermark at 85%' "${disk%%.*}" '' ''
        tune_budget "$name" "$heap_max"
    done <<< "$(run_t 5 curl -s -m 3 'http://127.0.0.1:9200/_cat/nodes?h=name,heap.percent,heap.max,ram.max,disk.used_percent&bytes=b' 2>/dev/null | clean)"
}

tune_mongo() {
    local client=mongosh out cache used conn avail ver group rec why up ram=$((R_MEM_TOTAL * 1024))
    [[ -n $(sig_list RUNNING '^MongoDB') ]] || return 0
    has mongosh || client=mongo
    has "$client" || return 0
    # mongosh keeps a log and a config in its home folder, and reports usage unless told not to.
    # A home inside /proc cannot be created, even by root.
    out=$(run_t 8 env HOME=/proc/nonexistent DO_NOT_TRACK=1 "$client" --quiet --norc --eval 'var s = db.serverStatus(), c = s.wiredTiger.cache;
        print("version\t" + s.version); print("uptime\t" + s.uptime); print("cache\t" + c["maximum bytes configured"]);
        print("used\t" + c["bytes currently in the cache"]); print("conn\t" + s.connections.current);
        print("avail\t" + s.connections.available);' 2>/dev/null | clean)
    if [[ -z $out || $out == *rror* ]]; then tune_note MongoDB 'It needs a login, so its limits could not be read.'; return 0; fi
    group="MongoDB $(tune_get "$out" version)"
    cache=$(tune_get "$out" cache)
    used=$(tune_get "$out" used)
    conn=$(tune_get "$out" conn)
    avail=$(tune_get "$out" avail)
    up=$(tune_get "$out" uptime)
    tune_too_young "$group" "$up"
    rec='' why=''
    if ((up >= TUNE_MATURE && cache > 0 && used * 100 / cache >= 95 && cache * 3 / 2 < ram * 3 / 4)); then
        rec=$(tune_round "$((cache * 3 / 2))") why='The WiredTiger cache is full. Check it stays within RAM.'
    fi
    tune_row "$group" wiredTigerCacheSizeGB "$(tune_size "$cache")" "$(tune_size "$used") used" "$(tune_pct "$used" "$cache")" "${rec:+$(tune_size "$rec")}" "$why" 'restart'
    tune_row "$group" maxIncomingConnections "$((conn + avail))" "$conn now" "$(tune_pct "$conn" "$((conn + avail))")" '' ''
    tune_budget MongoDB "$cache"
}

tune_haproxy() {
    local sock out max now group rec why
    [[ -n $(sig_list RUNNING '^HAProxy') ]] && has socat || return 0
    for sock in /run/haproxy/admin.sock /var/run/haproxy.sock /var/lib/haproxy/stats /run/haproxy.sock; do
        [[ -S $sock ]] || continue
        out=$(printf 'show info\n' | timeout 3 socat - "UNIX-CONNECT:$sock" 2>/dev/null | tr -d '\r' | sed 's/: /\t/')
        break
    done
    if [[ -z ${out:-} ]]; then tune_note HAProxy 'No stats socket was found, so live numbers are missing.'; return 0; fi
    group="HAProxy $(tune_get "$out" Version)"
    max=$(tune_get "$out" Maxconn)
    now=$(tune_get "$out" CurrConns)
    tune_too_young "$group" "$(tune_get "$out" Uptime_sec)"
    rec='' why=''
    if (($(tune_get "$out" Uptime_sec) >= TUNE_MATURE && max > 0 && now * 100 / max >= 80)); then rec=$((max * 3 / 2)) why="$now of $max connections are in use."; fi
    tune_row "$group" maxconn "$max" "$now now" "$(tune_pct "$now" "$max")" "$rec" "$why" 'reload'
}

tune_varnish() {
    local stats used free nuked hit miss group rec why
    [[ -n $(sig_list RUNNING '^Varnish') ]] && has varnishstat || return 0
    stats=$(run_t 5 varnishstat -1 2>/dev/null | awk '{ print $1 "\t" $2 }')
    [[ -n $stats ]] || return 0
    group="Varnish $(run_t 3 varnishd -V 2>&1 | sed -n 's/.*varnish-\([0-9.]*\).*/\1/p' | head -n 1)"
    used=$(tune_get "$stats" SMA.s0.g_bytes)
    free=$(tune_get "$stats" SMA.s0.g_space)
    nuked=$(tune_get "$stats" MAIN.n_lru_nuked)
    hit=$(tune_get "$stats" MAIN.cache_hit)
    miss=$(tune_get "$stats" MAIN.cache_miss)
    tune_too_young "$group" "$(tune_get "$stats" MAIN.uptime)"
    rec='' why=''
    if (($(tune_get "$stats" MAIN.uptime) >= TUNE_MATURE && nuked > 0)); then rec=$(tune_round "$(((used + free) * 3 / 2))") why="$nuked objects were pushed out for lack of room."; fi
    tune_row "$group" 'malloc storage' "$(tune_size "$((used + free))")" "$(tune_size "$used") used" "$(tune_pct "$used" "$((used + free))")" "${rec:+$(tune_size "$rec")}" "$why" 'restart'
    tune_note "$group" "$(tune_pct "$hit" "$((hit + miss))")% cache hit rate."
    tune_budget Varnish "$((used + free))"
}

tune_litespeed() {
    local report max now group
    [[ -n $(sig_list RUNNING '^(LiteSpeed server|OpenLiteSpeed)') ]] || return 0
    report=$(cat /tmp/lshttpd/.rtreport 2>/dev/null | clean)
    if [[ -z $report ]]; then tune_note LiteSpeed 'Its live report was not found.'; return 0; fi
    group="LiteSpeed $(sed -n 's/^VERSION: *LiteSpeed Web Server\/[A-Za-z]*\/\([0-9.]*\).*/\1/p' <<< "$report" | head -n 1)"
    max=$(sed -n 's/.*MAXCONN: *\([0-9]*\).*/\1/p' <<< "$report" | head -n 1)
    now=$(sed -n 's/.*PLAINCONN: *\([0-9]*\).*/\1/p' <<< "$report" | head -n 1)
    [[ $max =~ ^[0-9]+$ ]] && tune_row "$group" maxConnections "$max" "${now:-0} now" "$(tune_pct "${now:-0}" "$max")" '' ''
}

# The stock server.xml carries a maxThreads inside a comment, and the number of the real
# connector is what counts. Comments can span lines, so they go first.
tomcat_threads() {
    awk '{
        line = $0
        while (line != "") {
            if (off) {
                p = index(line, "-->")
                if (!p) next
                line = substr(line, p + 3); off = 0
            } else {
                p = index(line, "<!--")
                if (!p) { print line; next }
                print substr(line, 1, p - 1)
                line = substr(line, p + 4); off = 1
            }
        }
    }' "$1" 2>/dev/null | grep -o 'maxThreads="[0-9]*"' | head -n 1 | tr -dc 0-9
}

tune_tomcat() {
    local file threads pid busy heap group
    [[ -n $(sig_list RUNNING '^Apache Tomcat') ]] || return 0
    for file in /etc/tomcat*/server.xml /opt/tomcat/conf/server.xml /usr/local/tomcat/conf/server.xml; do
        [[ -r $file ]] && break
    done
    [[ -r ${file:-} ]] || return 0
    threads=$(tomcat_threads "$file")
    threads=${threads:-200}
    pid=$(ps -eo pid=,args= 2>/dev/null | awk '/org\.apache\.catalina/ { print $1; exit }')
    group=Tomcat
    busy=0
    if [[ -n $pid ]]; then
        busy=$(awk '/^Threads:/ { print $2 }' "/proc/$pid/status" 2>/dev/null)
        # Only the heap flag is taken from the command line. Arguments can hold passwords.
        heap=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep '^-Xmx' | head -n 1)
    fi
    tune_row "$group" maxThreads "$threads" "${busy:-0} JVM threads in all" 0 '' ''
    tune_row "$group" 'JVM heap' "${heap:-default}" 'set with -Xmx' 0 '' ''
}

# Prometheus text as name<TAB>value, with labels dropped and series added up.
tune_fetch() { run_t 5 curl -fs -m 3 "$1" 2>/dev/null | clean; }
tune_metrics() {
    awk '/^#/ { next } { sub(/\{[^}]*\}/, ""); if (NF >= 2) s[$1] += $2 } END { for (k in s) printf "%s\t%.0f\n", k, s[k] }' <<< "$1"
}

# Open files as a service counts them itself. The row appears only if it reports both numbers.
tune_metric_files() {
    local group=$1 data=$2 age=$3 open max rec='' why=''
    open=$(tune_get "$data" process_open_fds)
    max=$(tune_get "$data" process_max_fds)
    ((max > 0)) || return 0
    if ((age >= TUNE_MATURE && open * 100 / max >= 70)); then
        rec=$((max * 2)) why="$open of $max file handles are in use. Reaching the limit makes new connections fail."
    fi
    tune_row "$group" 'open files' "$max" "$open open" "$(tune_pct "$open" "$max")" "$rec" "$why" 'restart'
}

tune_disk_row() {
    local group=$1 label=$2 path=$3 used free size pct
    read -r size used free pct <<< "$(run_t 5 df -Pk "$path" 2>/dev/null | awk 'NR == 2 { sub(/%/, "", $5); print $2, $3, $4, $5 }')"
    [[ $size =~ ^[0-9]+$ ]] || return 0
    tune_row "$group" "disk $label" "$(human_kb "$size")" "$(human_kb "$free") free" "${pct:-0}" '' ''
}

tune_rabbitmq() {
    local raw data group=RabbitMQ limit used avail low up rec why version ram=$((R_MEM_TOTAL * 1024))
    [[ -n $(sig_list RUNNING '^RabbitMQ') ]] || return 0
    if has curl; then raw=$(tune_fetch http://127.0.0.1:15692/metrics); fi
    if [[ -z ${raw:-} ]]; then
        tune_note "$group" 'Its Prometheus port 15692 did not answer, so limits were not read. rabbitmqctl is left out on purpose: its wrapper switches user, which writes to the auth log.'
        return 0
    fi
    data=$(tune_metrics "$raw")
    version=$(sed -n 's/.*rabbitmq_version="\([0-9.]*\)".*/\1/p' <<< "$raw" | head -n 1)
    [[ -z $version ]] || group="RabbitMQ $version"
    up=$(tune_get "$data" rabbitmq_erlang_uptime_seconds)
    tune_too_young "$group" "$up"
    limit=$(tune_get "$data" rabbitmq_resident_memory_limit_bytes)
    used=$(tune_get "$data" rabbitmq_process_resident_memory_bytes)
    rec='' why=''
    if ((limit > 0)); then
        if ((up >= TUNE_MATURE && $(tune_get "$data" rabbitmq_alarms_memory_used_watermark) > 0 && limit * 3 / 2 < ram * 3 / 4)); then
            rec=$((limit * 3 / 2)) why='The memory alarm is on, so publishers are blocked. Consuming the queues comes first.'
        fi
        tune_row "$group" vm_memory_high_watermark "$(tune_size "$limit")" "$(tune_size "$used") used" "$(tune_pct "$used" "$limit")" "${rec:+$(tune_size "$rec")}" "$why" 'restart' "$rec"
        tune_budget RabbitMQ "$limit"
    fi
    avail=$(tune_get "$data" rabbitmq_disk_space_available_bytes)
    low=$(tune_get "$data" rabbitmq_disk_space_available_limit_bytes)
    if ((low > 0 && avail > 0)); then
        tune_row "$group" disk_free_limit "$(tune_size "$low")" "$(tune_size "$avail") free" "$(tune_pct "$low" "$avail")" '' ''
    fi
    tune_metric_files "$group" "$(awk -F '\t' '$1 == "rabbitmq_process_open_fds" { print "process_open_fds\t" $2 } $1 == "rabbitmq_process_max_fds" { print "process_max_fds\t" $2 }' <<< "$data")" "$up"
    tune_note "$group" "$(tune_get "$data" rabbitmq_connections) connections, $(tune_get "$data" rabbitmq_queue_messages) messages in queues."
}

# The query goes in the URL of a read-only GET. log_queries keeps it out of its query log.
tune_clickhouse_query() {
    run_t 5 curl -fs -m 4 -G --data-urlencode "query=$1" --data log_queries=0 http://127.0.0.1:8123/ 2>/dev/null | clean
}

tune_clickhouse() {
    local version group settings metrics events up max now mem limit ratio rec why
    [[ -n $(sig_list RUNNING '^ClickHouse') ]] || return 0
    if ! has curl || ! version=$(tune_clickhouse_query 'SELECT version()') || [[ -z $version ]]; then
        tune_note ClickHouse 'Port 8123 did not answer without a password, so its limits could not be read.'
        return 0
    fi
    group="ClickHouse $version"
    up=$(tune_clickhouse_query 'SELECT uptime()')
    [[ $up =~ ^[0-9]+$ ]] || up=0
    tune_too_young "$group" "$up"
    metrics=$(tune_clickhouse_query "SELECT metric, value FROM system.metrics WHERE metric IN ('TCPConnection','HTTPConnection','Query','MemoryTracking') FORMAT TabSeparated")
    events=$(tune_clickhouse_query "SELECT event, value FROM system.events WHERE event IN ('RejectedInserts','DelayedInserts','QueryMemoryLimitExceeded') FORMAT TabSeparated")
    # server_settings only exists on 23.4 and newer.
    settings=$(tune_clickhouse_query "SELECT name, value FROM system.server_settings WHERE name IN ('max_connections','max_concurrent_queries','max_server_memory_usage','max_server_memory_usage_to_ram_ratio') FORMAT TabSeparated")
    max=$(tune_get "$settings" max_connections)
    now=$(($(tune_get "$metrics" TCPConnection) + $(tune_get "$metrics" HTTPConnection)))
    if ((max > 0)); then
        rec='' why=''
        if ((up >= TUNE_MATURE && now * 100 / max >= 85)); then rec=$((max * 3 / 2)) why="$now of $max connections are in use."; fi
        tune_row "$group" max_connections "$max" "$now now" "$(tune_pct "$now" "$max")" "$rec" "$why" 'restart'
    fi
    max=$(tune_get "$settings" max_concurrent_queries)
    now=$(tune_get "$metrics" Query)
    if ((max > 0)); then tune_row "$group" max_concurrent_queries "$max" "$now running" "$(tune_pct "$now" "$max")" '' ''; fi
    mem=$(tune_get "$metrics" MemoryTracking)
    limit=$(tune_get "$settings" max_server_memory_usage)
    ratio=$(tune_get "$settings" max_server_memory_usage_to_ram_ratio)
    if ((limit == 0)) && [[ $ratio != 0 ]]; then
        limit=$(awk -v r="$ratio" -v k="$R_MEM_TOTAL" 'BEGIN { printf "%.0f", r * k * 1024 }')
    fi
    if ((limit > 0)); then
        tune_row "$group" max_server_memory_usage "$(tune_size "$limit")" "$(tune_size "$mem") used" "$(tune_pct "$mem" "$limit")" '' ''
        tune_budget ClickHouse "$limit"
    fi
    if (($(tune_get "$events" RejectedInserts) > 0)); then
        tune_note "$group" "$(tune_get "$events" RejectedInserts) inserts were rejected for too many parts. Insert in bigger, rarer batches."
    fi
    if (($(tune_get "$events" QueryMemoryLimitExceeded) > 0)); then
        tune_note "$group" "$(tune_get "$events" QueryMemoryLimitExceeded) queries hit a memory limit."
    fi
}

tune_influx() {
    local raw data group=InfluxDB version
    [[ -n $(sig_list RUNNING '^InfluxDB') ]] || return 0
    has curl || { tune_note "$group" 'Reading it needs curl.'; return 0; }
    version=$(run_t 5 curl -s -m 3 -I http://127.0.0.1:8086/ping 2>/dev/null | clean | tr -d '\r' | awk -F ': *' 'tolower($1) == "x-influxdb-version" { print $2 }')
    [[ -n $version ]] || version=$(tune_fetch http://127.0.0.1:8086/health | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p')
    [[ -z $version ]] || group="InfluxDB $version"
    tune_note "$group" 'InfluxDB sets no memory limit of its own, so there is no limit to compare with.'
    raw=$(tune_fetch http://127.0.0.1:8086/metrics)
    if [[ -n $raw ]]; then
        data=$(tune_metrics "$raw")
        tune_note "$group" "It uses $(tune_size "$(tune_get "$data" go_memstats_alloc_bytes)") of heap right now."
        tune_metric_files "$group" "$data" 0
    fi
}

tune_minio() {
    local group=MinIO line path
    [[ -n $(sig_list RUNNING '^MinIO') ]] || return 0
    tune_note "$group" 'Its metrics need a token, so its limits could not be read.'
    # This file also holds the root password, so only this one line is looked at.
    line=$(awk -F= '$1 == "MINIO_VOLUMES" { print $2; exit }' "$LHA_ROOT/etc/default/minio" 2>/dev/null | clean | tr -d '"')
    for path in $line; do
        [[ $path == /* && $path != *'{'* ]] || continue
        tune_disk_row "$group" "$path" "$LHA_ROOT$path"
    done
}

tune_keepalived() {
    local group=Keepalived conf vips held=0 total=0 ip addresses
    [[ -n $(sig_list RUNNING '^Keepalived') ]] || return 0
    conf=$LHA_ROOT/etc/keepalived/keepalived.conf
    if [[ ! -r $conf ]]; then tune_note "$group" 'Its config cannot be read here.'; return 0; fi
    vips=$(awk '/virtual_ipaddress[ \t]*\{/ { on = 1; next } on && /\}/ { on = 0 } on && NF { sub(/\/.*/, "", $1); print $1 }' "$conf" | clean)
    addresses=$(run_t 3 ip -o addr show 2>/dev/null | clean)
    for ip in $vips; do
        ((total += 1))
        [[ $addresses != *" $ip/"* ]] || ((held += 1))
    done
    tune_note "$group" "This node holds $held of its $total virtual addresses now. Keepalived has no capacity limit to read."
}

tune_squid() {
    local out port max now up group=Squid version rec='' why='' mem
    [[ -n $(sig_list RUNNING '^Squid') ]] || return 0
    port=$(port_of squid)
    if has curl; then out=$(tune_fetch "http://127.0.0.1:${port:-3128}/squid-internal-mgr/info"); fi
    if [[ -z ${out:-} ]]; then tune_note "$group" 'Its manager page did not answer from this machine, so limits were not read.'; return 0; fi
    version=$(sed -n 's/.*Squid Object Cache: Version \([0-9.]*\).*/\1/p' <<< "$out" | head -n 1)
    [[ -z $version ]] || group="Squid $version"
    max=$(awk -F ':' '/Maximum number of file descriptors/ { gsub(/[^0-9]/, "", $2); print $2; exit }' <<< "$out")
    now=$(awk -F ':' '/Number of file desc currently in use/ { gsub(/[^0-9]/, "", $2); print $2; exit }' <<< "$out")
    up=$(awk -F ':' '/UP Time/ { sub(/\..*/, "", $2); gsub(/[^0-9]/, "", $2); print $2; exit }' <<< "$out")
    tune_too_young "$group" "${up:-0}"
    if [[ $max =~ ^[1-9][0-9]*$ && $now =~ ^[0-9]+$ ]]; then
        if ((${up:-0} >= TUNE_MATURE && now * 100 / max >= 70)); then rec=$((max * 2)) why="$now of $max file handles are in use."; fi
        tune_row "$group" max_filedescriptors "$max" "$now open" "$(tune_pct "$now" "$max")" "$rec" "$why" 'restart'
    fi
    mem=$(awk -F ':' '/Storage Mem capacity/ { sub(/%.*/, "", $2); gsub(/[^0-9.]/, "", $2); printf "%d", $2; exit }' <<< "$out")
    if [[ $mem =~ ^[0-9]+$ ]]; then tune_row "$group" cache_mem 'config' "$mem% used" "$mem" '' ''; fi
}

# Caddy and Traefik: Go programs with their numbers on a metrics page, if that page is on.
tune_go_proxy() {
    local name=$1 url=$2 raw data group version
    group=$name
    raw=$(tune_fetch "$url")
    if [[ -z $raw ]]; then tune_note "$group" 'Its metrics page is off, so only the numbers below for its process are known.'; return 0; fi
    data=$(tune_metrics "$raw")
    version=$(sed -n 's/.*[^a-z_]version="\(v*[0-9][^"]*\)".*/\1/p' <<< "$raw" | head -n 1)
    [[ -z $version ]] || group="$name $version"
    tune_metric_files "$group" "$data" "$3"
    tune_note "$group" "It uses $(tune_size "$(tune_get "$data" go_memstats_alloc_bytes)") of heap right now."
}

tune_caddy() {
    [[ -n $(sig_list RUNNING '^Caddy') ]] || return 0
    has curl || return 0
    tune_go_proxy Caddy http://127.0.0.1:2019/metrics "$(tune_age caddy)"
}

tune_traefik() {
    local port
    [[ -n $(sig_list RUNNING '^Traefik') ]] || return 0
    has curl || return 0
    # Port 8080 is common, so ask it only when Traefik itself holds it.
    for port in 8080 8082; do
        if [[ $(port_owner "$port") == traefik ]]; then
            tune_go_proxy Traefik "http://127.0.0.1:$port/metrics" "$(tune_age traefik)"
            return 0
        fi
    done
    tune_note Traefik 'No metrics port was found, so only the numbers below for its process are known.'
}

# The fullest listen queue of a program: "waiting limit". It needs ss, so it can be empty.
tune_backlog() {
    ss_quiet tcp_diag unix_diag || return 0
    run_t 3 ss -lntxp 2>/dev/null | clean | grep -F "\"$1\"" | awk '{
        for (i = 1; i < NF; i++) if ($i == "LISTEN" && $(i + 2) + 0 > 0) {
            q = $(i + 1) + 0; l = $(i + 2) + 0
            if (l && q * 100 / l >= best) { best = q * 100 / l; w = q; m = l }
        }
    } END { if (m) print w, m }'
}

# Gunicorn and uWSGI: pre-forked workers. A full listen queue is the proof they are all busy.
tune_workers() {
    local name=$1 comm=$2 setting=$3 rows count cpu rss waiting limit rec='' why='' age
    rows=$(ps -eo pid=,ppid=,pcpu=,rss=,comm= 2>/dev/null | awk -v c="$comm" '$5 == c')
    if [[ -z $rows ]]; then tune_note "$name" "Its workers could not be told apart from other programs, so they were not counted."; return 0; fi
    read -r count cpu rss <<< "$(awk '{ id[$1] = 1; up[NR] = $2; c[NR] = $3; m[NR] = $4 }
        END {
            for (i = 1; i <= NR; i++) if (up[i] in id) { n++; tc += c[i]; tm += m[i] }
            if (!n) for (i = 1; i <= NR; i++) { n++; tc += c[i]; tm += m[i] }
            printf "%d %d %d\n", n, tc / n, tm / n
        }' <<< "$rows")"
    age=$(tune_age "$comm")
    tune_too_young "$name" "$age"
    read -r waiting limit <<< "$(tune_backlog "$comm")"
    if [[ $limit =~ ^[1-9][0-9]*$ ]]; then
        if ((age >= TUNE_MATURE && waiting * 100 / limit >= 50)); then
            rec=$((count * 3 / 2 > count ? count * 3 / 2 : count + 1)) why="$waiting requests wait in a queue of $limit, so all workers are busy. Look for slow requests too."
        fi
        tune_row "$name" 'listen queue' "$limit" "$waiting waiting" "$(tune_pct "$waiting" "$limit")" '' ''
    fi
    tune_row "$name" "$setting" "$count" "$(human_kb "$rss") each, ${cpu}% CPU" "$cpu" "$rec" "$why" 'restart'
    tune_budget "$name" "$((count * rss * 1024))"
}

# One flag of a process, without reading the rest: arguments can hold passwords.
proc_flag() {
    local arg found=''
    while IFS= read -r -d '' arg; do
        case $arg in "$2"*) found=${arg#"$2"} ;; esac
    done < "$1" 2>/dev/null
    printf '%s' "$found"
}

# 512m, 2g or 1048576 in bytes.
size_bytes() {
    local text=$1 number=${1%[kKmMgGtT]}
    [[ $number =~ ^[0-9]+$ ]] || { printf 0; return 0; }
    case $text in
        *[kK]) printf '%d' "$((number * 1024))" ;;
        *[mM]) printf '%d' "$((number * 1048576))" ;;
        *[gG]) printf '%d' "$((number * 1073741824))" ;;
        *[tT]) printf '%d' "$((number * 1099511627776))" ;;
        *) printf '%d' "$number" ;;
    esac
}

# Every JVM, whatever it runs. Inside numbers need jstat or JMX, which are left out on purpose.
tune_jvm() {
    local pid rss name heap bytes shown=0
    while read -r pid rss; do
        [[ -n $pid ]] || continue
        ((shown < 6)) || break
        ((shown += 1))
        runtime_role "/proc/$pid/cmdline"
        name=${REPLY:-java}
        heap=$(proc_flag "/proc/$pid/cmdline" -Xmx)
        bytes=$(size_bytes "$heap")
        tune_row 'JVM services' "$name (pid $pid) heap" "${heap:-JVM default}" "$(human_kb "$rss") in RAM" "$(tune_pct "$((rss * 1024))" "$bytes")" '' ''
        case $name in
            elasticsearch|opensearch) ;;
            *) ((bytes == 0)) || tune_budget "JVM $name" "$bytes" ;;
        esac
    done <<< "$(ps -eo pid=,rss=,comm= 2>/dev/null | awk '$3 == "java" { print $2, $1 }' | sort -rn | awk '{ print $2, $1 }')"
    if ((shown > 0)); then
        tune_note 'JVM services' 'RAM use includes more than heap. Use inside the heap needs jstat or JMX, which this tool does not start, so there is no advice here.'
    fi
}

tune_node() {
    local pid rss heap bytes pct shown=0 rec why age
    while read -r pid rss; do
        [[ -n $pid ]] || continue
        ((shown < 5)) || break
        ((shown += 1))
        heap=$(proc_flag "/proc/$pid/cmdline" --max-old-space-size=)
        rec='' why=''
        if [[ $heap =~ ^[0-9]+$ ]]; then
            bytes=$((heap * 1048576))
            pct=$(tune_pct "$((rss * 1024))" "$bytes")
            age=$(tune_age_pid "$pid")
            if ((${age:-0} >= TUNE_MATURE && pct >= 100)); then
                rec="$((heap * 3 / 2))" why='Memory is past its heap limit, so garbage collection works hard. A leak is the first suspect.'
            fi
            tune_row Node.js "pid $pid heap, MiB" "$heap" "$(human_kb "$rss") in RAM" "$pct" "$rec" "$why" 'restart'
        else
            tune_row Node.js "pid $pid" 'no limit set' "$(human_kb "$rss") in RAM" 0 '' ''
        fi
    done <<< "$(ps -eo pid=,rss=,comm= 2>/dev/null | awk '$3 == "node" || $3 == "nodejs" { print $2, $1 }' | sort -rn | awk '{ print $2, $1 }')"
    if ((shown > 0)); then
        tune_note Node.js 'A heap limit is only known from --max-old-space-size on the command line. NODE_OPTIONS is not read, because environments can hold secrets.'
    fi
}

tune_kafka() {
    local group=Kafka file jar version dirs dir
    [[ -n $(sig_list RUNNING '^Apache Kafka') ]] || return 0
    for jar in "$LHA_ROOT"/opt/kafka/libs/kafka_*.jar "$LHA_ROOT"/usr/share/java/kafka/kafka_*.jar "$LHA_ROOT"/usr/share/kafka/libs/kafka_*.jar; do
        case $jar in *-test*|*-sources*|*-javadoc*|*'*'*) continue ;; esac
        version=${jar##*-} version=${version%.jar}
        break
    done
    [[ -z ${version:-} ]] || group="Kafka $version"
    for file in "$LHA_ROOT"/etc/kafka/server.properties "$LHA_ROOT"/etc/kafka/kraft/server.properties \
        "$LHA_ROOT"/opt/kafka/config/server.properties "$LHA_ROOT"/opt/kafka/config/kraft/server.properties; do
        [[ -r $file ]] || continue
        dirs=$(awk -F= '$1 == "log.dirs" || $1 == "log.dir" { print $2; exit }' "$file" | clean | tr ',' ' ')
        break
    done
    for dir in ${dirs:-}; do [[ ! -d $LHA_ROOT$dir ]] || tune_disk_row "$group" "$dir" "$LHA_ROOT$dir"; done
    tune_note "$group" 'Broker limits live in JMX, which this tool does not open. Open files, threads and heap are shown below.'
}

tune_cassandra() {
    local group=Cassandra conf jar version dirs dir
    [[ -n $(sig_list RUNNING '^Apache Cassandra') ]] || return 0
    for jar in "$LHA_ROOT"/usr/share/cassandra/apache-cassandra-[0-9]*.jar "$LHA_ROOT"/opt/cassandra/lib/apache-cassandra-[0-9]*.jar; do
        case $jar in *'*'*) continue ;; esac
        version=${jar##*apache-cassandra-} version=${version%.jar}
        break
    done
    [[ -z ${version:-} ]] || group="Cassandra $version"
    for conf in "$LHA_ROOT"/etc/cassandra/cassandra.yaml "$LHA_ROOT"/opt/cassandra/conf/cassandra.yaml; do
        [[ -r $conf ]] || continue
        dirs=$(awk '/^data_file_directories:/ { on = 1; next } on && /^[ \t]*-/ { print $2; next } on { exit }' "$conf" | clean)
        break
    done
    for dir in ${dirs:-/var/lib/cassandra/data}; do [[ ! -d $LHA_ROOT$dir ]] || tune_disk_row "$group" "$dir" "$LHA_ROOT$dir"; done
    tune_note "$group" 'nodetool is left out on purpose: it writes a history file. Heap, threads and open files are shown below.'
}

# Prometheus only. The ceph command is left out, because nothing proves it writes nothing.
tune_ceph() {
    local raw data group=Ceph status total used word
    [[ -n $(sig_list RUNNING '^Ceph') ]] || return 0
    if has curl; then raw=$(tune_fetch http://127.0.0.1:9283/metrics); fi
    if [[ -z ${raw:-} ]]; then
        tune_note "$group" 'The Prometheus module of ceph-mgr did not answer here, so the cluster state was not read.'
        return 0
    fi
    data=$(tune_metrics "$raw")
    total=$(tune_get "$data" ceph_cluster_total_bytes)
    used=$(tune_get "$data" ceph_cluster_total_used_bytes)
    if ((total > 0)); then
        tune_row "$group" 'raw capacity' "$(tune_size "$total")" "$(tune_size "$used") used" "$(tune_pct "$used" "$total")" '' ''
    fi
    status=$(tune_get "$data" ceph_health_status)
    case $status in 0) word=HEALTH_OK ;; 1) word=HEALTH_WARN ;; *) word=HEALTH_ERR ;; esac
    tune_note "$group" "Cluster health is $word, with $(tune_get "$data" ceph_osd_up) OSDs up of $(tune_get "$data" ceph_osd_in) in."
}

# Plain state files. The gluster command logs every call to its own log, so it stays out.
tune_gluster() {
    local base=$LHA_ROOT/var/lib/glusterd group=GlusterFS info name state count brick path peers=0
    [[ -n $(sig_list RUNNING '^GlusterFS') ]] || return 0
    if [[ ! -d $base/vols ]]; then tune_note "$group" 'Its state folder cannot be read here.'; return 0; fi
    for info in "$base"/vols/*/info; do
        [[ -r $info ]] || continue
        name=${info%/info} name=${name##*/}
        state=$(awk -F= '$1 == "status" { print $2; exit }' "$info")
        count=$(awk -F= '$1 == "count" { print $2; exit }' "$info")
        if [[ $state != 1 ]]; then tune_note "$group" "Volume $name is not started."; fi
        for brick in "$base/vols/$name"/bricks/*; do
            [[ -r $brick ]] || continue
            path=$(awk -F= '$1 == "path" { print $2; exit }' "$brick")
            [[ -n $path && -d $LHA_ROOT$path ]] || continue
            tune_disk_row "$group" "$name:$path" "$LHA_ROOT$path"
        done
        tune_note "$group" "Volume $name has ${count:-0} bricks."
    done
    for info in "$base"/peers/*; do [[ ! -f $info ]] || ((peers += 1)); done
    tune_note "$group" "$peers other servers in this pool."
}

tune_containers() {
    local line name mem used limit pct engine count=0 unlimited=0
    ((CT_N > 0)) || return 0
    engine=${CT_ENGINE[0]}
    [[ $engine != crictl ]] || return 0
    while IFS='|' read -r name pct used limit; do
        [[ -n $name ]] || continue
        pct=${pct%%.*} pct=${pct%\%}
        [[ $pct =~ ^[0-9]+$ ]] || pct=0
        if [[ $limit == "$(tune_host_limit)" ]]; then ((unlimited += 1)); continue; fi
        ((count < 8)) || continue
        ((count += 1))
        tune_row Containers "$name" "$limit" "$used used" "$pct" '' ''
    done <<< "$(run_t 10 "$engine" stats --no-stream --format '{{.Name}}|{{.MemPerc}}|{{.MemUsage}}' 2>/dev/null | clean | sed 's| / |\||' | awk -F '|' '{ print $1 "|" $2 "|" $3 "|" $4 }')"
    if ((unlimited > 0)); then tune_note Containers "$unlimited containers have no memory limit, so one of them can starve the rest."; fi
}
# docker stats shows host RAM as the limit of a container that has none.
tune_host_limit() {
    awk -v k="$R_MEM_TOTAL" 'BEGIN { printf "%.4gGiB", k / 1048576 }'
}

tune_kube() {
    local name cpu cpct mem mpct
    [[ ${K_API:-no} == yes ]] || return 0
    while read -r name cpu cpct mem mpct; do
        [[ -n $name ]] || continue
        tune_row Kubernetes "node $name memory" "$mem" 'in use' "${mpct%\%}" '' ''
        tune_row Kubernetes "node $name CPU" "$cpu" 'in use' "${cpct%\%}" '' ''
    done <<< "$(ku top nodes --no-headers | clean | head -n 12)"
    [[ -n $TUNE_ROWS && $TUNE_ROWS == *'Kubernetes|'* ]] || tune_note Kubernetes 'Live usage needs metrics-server.'
}

tune_kernel() {
    local group='Linux kernel' value overflows tw low high range rec why thp netstat
    netstat=$(awk 'NR % 2 == 1 { split($0, k) } NR % 2 == 0 { n = split($0, v); for (i = 2; i <= n; i++) print k[i] "\t" v[i] }' /proc/net/netstat 2>/dev/null)
    value=$(cat /proc/sys/net/core/somaxconn 2>/dev/null)
    overflows=$(tune_get "$netstat" ListenOverflows)
    if [[ $value =~ ^[0-9]+$ ]]; then
        rec='' why=''
        if ((overflows > 0 && value < 65535)); then
            rec=$((value * 2 > 4096 ? value * 2 : 4096))
            why="Listen queues overflowed $overflows times since boot, and connections were dropped. Busy services also need a matching backlog of their own."
        fi
        tune_row "$group" net.core.somaxconn "$value" "$overflows overflows" 0 "$rec" "$why" 'live'
    fi
    read -r low high 2>/dev/null < "$LHA_ROOT/proc/sys/net/ipv4/ip_local_port_range"
    if [[ $low =~ ^[0-9]+$ ]]; then
        range=$((high - low + 1))
        # Only sockets on a port of this range are spent outgoing ports. A web server collects
        # plenty of TIME-WAIT on port 80, and that costs no port at all.
        tw=$(tcp_count 06 "$low" "$high")
        rec='' why=''
        if ((tw * 100 / range >= 70 && low > 10240)); then
            # Below this, an outgoing connection can sit on a port a service wants at its next start.
            rec="10240 $high" why='Outgoing ports are running out, which fails new connections to databases and backends.'
        fi
        tune_row "$group" ip_local_port_range "$low-$high" "$tw in TIME-WAIT" "$(tune_pct "$tw" "$range")" "$rec" "$why" 'live'
    fi
    if [[ -r /proc/sys/fs/file-nr ]]; then
        read -r value _ high < /proc/sys/fs/file-nr
        tune_row "$group" fs.file-max "$high" "$value open" "$(tune_pct "$value" "$high")" '' ''
    fi
    if [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
        read -r high < /proc/sys/net/netfilter/nf_conntrack_max
        read -r value < /proc/sys/net/netfilter/nf_conntrack_count
        tune_row "$group" nf_conntrack_max "$high" "$value tracked" "$(tune_pct "$value" "$high")" '' ''
    fi
    value=$(cat /proc/sys/vm/swappiness 2>/dev/null)
    if [[ $value =~ ^[0-9]+$ ]] && ((value > 10 && R_SWAP_USED > 0)) && [[ -n $(sig_list RUNNING '^(MariaDB|MySQL|PostgreSQL|MongoDB|Redis)') ]]; then
        tune_row "$group" vm.swappiness "$value" "$(human_kb "$R_SWAP_USED") in swap" 0 10 'A database in swap is very slow. This keeps it in RAM longer.' 'live'
    fi
    thp=$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)
    if [[ $thp == always ]] && [[ -n $(sig_list RUNNING '^(Redis|Valkey|MongoDB|MariaDB|MySQL)') ]]; then
        tune_row "$group" transparent_hugepage always 'databases running' 0 madvise 'Redis, MongoDB and MariaDB advise against this mode. It causes latency spikes.' 'live'
    fi
}

# The layer for everything without its own rules: any program with an open port.
tune_any_program() {
    local pid proc fds limit threads rss pct row='' done_pids=' ' rows=''
    while read -r _ _ _ _ proc pid; do
        [[ $pid =~ ^[0-9]+$ && $done_pids != *" $pid "* ]] || continue
        done_pids+="$pid "
        [[ -r /proc/$pid/limits ]] || continue
        limit=$(awk '/^Max open files/ { print $4 }' "/proc/$pid/limits")
        [[ $limit =~ ^[0-9]+$ ]] || continue
        fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l | tr -d ' ')
        threads=$(awk '/^Threads:/ { print $2 }' "/proc/$pid/status" 2>/dev/null)
        rss=$(tune_real_kb "$pid")
        rows+="$(tune_pct "$fds" "$limit") $proc $limit $fds ${threads:-0} $rss"$'\n'
    done <<< "$NET_ROWS"
    while read -r pct proc limit fds threads rss; do
        [[ -n $proc ]] || continue
        if ((pct >= 70 && $(tune_age "$proc") >= TUNE_MATURE)); then
            tune_row 'Every program with an open port' "$proc open files" "$limit" "$fds open, $threads threads, $(human_kb "$rss")" "$pct" "$((limit * 2))" \
                'It is near its open file limit. Reaching it makes new connections fail.' 'restart'
        else
            tune_row 'Every program with an open port' "$proc open files" "$limit" "$fds open, $threads threads, $(human_kb "$rss")" "$pct" '' ''
        fi
    done <<< "$(sort -rn <<< "$rows" | head -n 12)"
}

tune_collect() {
    [[ ${tune_done:-no} != yes ]] || return 0
    tune_done=yes
    TUNE_ROWS='' TUNE_NOTES='' TUNE_BUDGET='' TUNE_APPLY=''
    tune_mysql
    tune_postgres
    [[ -z $(sig_list RUNNING '^Redis server') ]] || tune_redis Redis redis-cli
    [[ -z $(sig_list RUNNING '^Valkey server') ]] || tune_redis Valkey valkey-cli
    tune_memcached
    tune_mongo
    tune_elastic Elasticsearch
    tune_elastic OpenSearch
    tune_nginx
    tune_apache
    tune_litespeed
    tune_haproxy
    tune_varnish
    tune_phpfpm
    tune_tomcat
    tune_rabbitmq
    tune_kafka
    tune_cassandra
    tune_clickhouse
    tune_influx
    tune_minio
    tune_ceph
    tune_gluster
    tune_keepalived
    tune_squid
    tune_caddy
    tune_traefik
    [[ -z $(sig_list RUNNING '^Gunicorn') ]] || tune_workers Gunicorn gunicorn workers
    [[ -z $(sig_list RUNNING '^uWSGI') ]] || tune_workers uWSGI uwsgi processes
    tune_node
    tune_jvm
    tune_containers
    tune_kube
    tune_kernel
    tune_any_program
}

tune_print_group() {
    local group=$1 setting now used pct rec why how color
    sub "$group"
    printf '  %-28s %-12s %-30s %5s  %s\n' SETTING NOW USED FULL ADVICE
    while IFS='|' read -r _ setting now used pct rec why how; do
        # kubectl top prints <unknown> for a node without metrics.
        [[ $pct =~ ^[0-9]+$ ]] || pct=0
        color=$c_grn
        if ((pct >= 90)); then color=$c_red; elif ((pct >= 75)); then color=$c_yel; fi
        if ((pct > 100)); then pct=100; fi
        printf '  %-28.28s %-12.12s %-30.30s %s%4s%%%s  ' "$setting" "$now" "$used" "$color" "$pct" "$c_off"
        if [[ -n $rec ]]; then printf '%s%s%s\n' "$c_bold" "$rec" "$c_off"; else printf '%sok%s\n' "$c_dim" "$c_off"; fi
        if [[ -n $rec ]]; then
            printf '    %sWhy: %s%s\n' "$c_dim" "$why" "$c_off"
            case $how in
                live) printf '    %sCan change while running.%s\n' "$c_dim" "$c_off" ;;
                reload) printf '    %sNeeds a config test and a reload.%s\n' "$c_dim" "$c_off" ;;
                restart) printf '    %sNeeds a planned restart.%s\n' "$c_dim" "$c_off" ;;
            esac
        fi
    done <<< "$(awk -F '|' -v g="$group" '$1 == g' <<< "$TUNE_ROWS")"
    while IFS='|' read -r _ text; do
        [[ -z $text ]] || printf '  %s%s%s\n' "$c_dim" "$text" "$c_off"
    done <<< "$(awk -F '|' -v g="$group" '$1 == g' <<< "$TUNE_NOTES")"
}

view_tune_one() {
    title 'Tuning' "$1"
    tune_print_group "$1"
}

view_budget() {
    tune_collect
    title 'Memory budget' 'What every service may use at once, compared with the RAM of this server.'
    tune_print_budget
}

tune_print_budget() {
    local name size total=0 ram=$((R_MEM_TOTAL * 1024))
    [[ -n $TUNE_BUDGET ]] || { printf '  No service reported memory limits.\n'; return 0; }
    while IFS='|' read -r name size; do
        [[ -n $name ]] || continue
        printf '  %-22s %12s\n' "$name" "$(tune_size "$size")"
        ((total += size))
    done <<< "$TUNE_BUDGET"
    printf '  %-22s %12s of %s RAM (%d%%)\n' Total "$(tune_size "$total")" "$(tune_size "$ram")" "$(tune_pct "$total" "$ram")"
    if ((total > ram)); then
        printf '  %s%s The limits allow more memory than this server has. Under a traffic spike, the kernel kills something.%s\n' "$c_red" "$g_warn" "$c_off"
        printf '  %sStart with the biggest: %s. Lower its limit toward the peak you really see.%s\n' "$c_dim" \
            "$(awk -F '|' 'NF && $2 + 0 > m + 0 { m = $2; n = $1 } END { print n }' <<< "$TUNE_BUDGET")" "$c_off"
    else
        printf '  %s%s The limits fit in RAM.%s\n' "$c_grn" "$g_ok" "$c_off"
    fi
}

tune_groups() { printf '%s%s' "$TUNE_ROWS" "$TUNE_NOTES" | awk -F '|' 'NF && !seen[$1]++ { print $1 }'; }

view_tune() {
    local group count
    tune_collect
    title 'Tuning and capacity' 'How full every limit is right now, and what the real load asks for.'
    kv 'Server now' "CPU $R_CPU%, load $R_LOAD1 on $H_CPUS cores, RAM $R_MEM_PCT%"
    if [[ -z $TUNE_ROWS$TUNE_NOTES ]]; then
        printf '\n  No database, cache or web server was found running here.\n'
        return 0
    fi
    while IFS= read -r group; do
        [[ -z $group ]] || tune_print_group "$group"
    done <<< "$(tune_groups)"
    sub 'Memory if everything peaks at once (estimate)'
    tune_print_budget
    count=$(awk -F '|' 'NF && $6 != "" { n++ } END { print n + 0 }' <<< "$TUNE_ROWS")
    printf '\n  %s changes are advised. Take them one at a time, and watch a day of traffic between them.\n' "$count"
    tips_begin
    tip 'mysqltuner' 'a second opinion for MySQL, if installed'
    tip 'SHOW GLOBAL STATUS;' 'the MySQL counters used here'
    tip 'redis-cli info' 'the Redis counters used here'
    tip 'nginx -T' 'the full nginx config as loaded'
}

# ---------------------------------------------------------------------------
# Trends: what the fixer recorded over time. This part only reads those files.
# Columns: time, cpu, load, ram, swap, fullest disk, connections, php workers, db connections, oom kills
# ---------------------------------------------------------------------------
TREND_DIR=${LHA_TREND_DIR:-/var/lib/linux-host-audit/history}

trend_read() { cat "$TREND_DIR"/*.csv 2>/dev/null | awk -F ',' -v from="$1" 'NF == 10 && $1 >= from'; }

# One metric: sparkline, then now, average, peak. Prints nothing if the column never had a value.
trend_line() {
    local label=$1 column=$2 unit=$3 limit=$4 data=$5 stats peak_at text
    local width=44
    stats=$(awk -F ',' -v c="$column" -v w="$width" -v limit="$limit" -v glyphs="${blocks[1]} ${blocks[2]} ${blocks[3]} ${blocks[4]} ${blocks[5]} ${blocks[6]} ${blocks[7]} ${blocks[8]}" '
        BEGIN { split(glyphs, g, " ") }
        { v[NR] = $c + 0; t[NR] = $1; s += $c; if (NR == 1 || $c + 0 > p) { p = $c + 0; pt = $1 } }
        END {
            if (NR == 0 || p == 0) exit
            top = (limit > 0 ? limit : p)
            n = (NR < w ? NR : w)
            line = ""
            for (i = 1; i <= n; i++) {
                a = int((i - 1) * NR / n) + 1; b = int(i * NR / n); sum = 0
                for (j = a; j <= b; j++) sum += v[j]
                level = int(sum / (b - a + 1) * 8 / top + 0.999)
                if (level < 1) level = 1
                if (level > 8) level = 8
                line = line g[level]
            }
            printf "%s\t%g\t%.1f\t%g\t%d\n", line, v[NR], s / NR, p, pt
        }' <<< "$data")
    [[ -n $stats ]] || return 0
    IFS=$'\t' read -r text now avg peak peak_at <<< "$stats"
    printf '  %-12s %s%s%s\n' "$label" "$c_cyan" "$text" "$c_off"
    printf '  %-12s %snow %s%s  average %s%s  peak %s%s at %s%s\n' '' "$c_dim" "$now" "$unit" "$avg" "$unit" "$peak" "$unit" \
        "$(date -d "@$peak_at" '+%b %d %H:%M' 2>/dev/null || printf '%s' "$peak_at")" "$c_off"
}

view_trends() {
    local window=${1:-week} seconds label data count first last days fill oom hour offset
    case $window in
        day) seconds=86400 label='last 24 hours' ;;
        month) seconds=2592000 label='last 30 days' ;;
        *) seconds=604800 label='last 7 days' ;;
    esac
    title "Trends: $label" 'Recorded here every few minutes, so this shows peaks a single look would miss.'
    data=$(trend_read "$(($(date +%s) - seconds))")
    count=$(awk 'END { print NR }' <<< "$data")
    if [[ -z $data ]]; then
        printf '  Nothing has been recorded yet. Recording is off until you turn it on:\n'
        tip 'sudo bash linux-host-fix.sh --trends-on' 'one light sample every 5 minutes'
        return 0
    fi
    first=$(head -n 1 <<< "$data" | cut -d, -f1)
    last=$(tail -n 1 <<< "$data" | cut -d, -f1)
    kv Samples "$count, over $(human_age "$((last - first))")"
    printf '\n'
    trend_line CPU 2 % 100 "$data"
    trend_line 'Load' 3 '' 0 "$data"
    trend_line RAM 4 % 100 "$data"
    trend_line Swap 5 % 100 "$data"
    trend_line 'Fullest disk' 6 % 100 "$data"
    trend_line Connections 7 '' 0 "$data"
    trend_line 'PHP workers' 8 '' 0 "$data"
    trend_line 'DB clients' 9 '' 0 "$data"

    sub 'What the history says'
    # A straight line through disk use. Needs two days, or a burst would look like a trend.
    if ((last - first >= 172800)); then
        days=$(awk -F ',' '{ x = ($1 - f) / 86400; if (NR == 1) { f = $1; x = 0 } sx += x; sy += $6; sxx += x * x; sxy += x * $6; y = $6 }
            END { d = NR * sxx - sx * sx; if (d <= 0) exit; m = (NR * sxy - sx * sy) / d
                  if (m < 0.05) print "flat"; else printf "%.0f %.2f\n", (100 - y) / m, m }' <<< "$data")
        if [[ $days == flat ]]; then
            printf '  Disk use is steady.\n'
        elif [[ -n $days ]]; then
            read -r fill days <<< "$days"
            printf '  %s%s At this rate the fullest disk fills in about %s days (%s%% a day).%s\n' "$c_yel" "$g_warn" "$fill" "$days" "$c_off"
        fi
    else
        printf '  Two days of samples are needed before forecasting disk use.\n'
    fi
    oom=$(awk -F ',' 'NR > 1 && $10 > p { n += $10 - p } { p = $10 } END { print n + 0 }' <<< "$data")
    if ((oom > 0)); then printf '  %s%s The kernel killed %s processes for memory in this period.%s\n' "$c_red" "$g_crit" "$oom" "$c_off"; fi
    # Hours in local time, so the busy hour matches the clock on the wall.
    offset=$(date +%z)
    offset=$(((10#${offset:1:2} * 3600 + 10#${offset:3:2} * 60) * (${offset:0:1}1)))
    hour=$(awk -F ',' -v o="$offset" '{ h = int((($1 + o) % 86400) / 3600); s[h] += $2; n[h]++ }
        END { for (h in s) if (s[h] / n[h] > b) { b = s[h] / n[h]; w = h } if (b > 0) printf "%02d:00, CPU averaging %.0f%%", w, b }' <<< "$data")
    [[ -z $hour ]] || printf '  Busiest hour: %s.\n' "$hour"
}

# ---------------------------------------------------------------------------
# Errors: what each running application wrote to its own log, grouped and explained.
# Read-only, and only a bounded tail of each file. Log lines can hold private data, so they
# appear in this view and nowhere else: not in --report, not in --json.
# ---------------------------------------------------------------------------
ERR_BYTES=2097152 ERR_LINES=3000 ERR_SHOW=6
ERR_ANY='error|fatal|panic|critical|severe|exception|failed|failure|denied|refused|timed out|out of memory'
ERR_QUIET='level=info|level=debug| info | debug |no error|0 errors|errors: 0|error_log|errorlog|on-failure'

# Regex~plain cause~next step. First match wins, so specific lines come before general ones.
err_hints() {
    cat <<'EOF'
worker_connections are not enough~Nginx ran out of connection slots~Raise worker_connections, and check it with --tune
upstream timed out~The app behind the web server answered too slowly~Find the slow requests in the app or database, then look at proxy_read_timeout
no live upstreams~Every backend of this site is marked down~Check that the backend service runs
upstream prematurely closed~The backend crashed or closed the connection mid-request~Read the error log of the backend
upstream sent too big header~The backend sent larger headers than the buffer allows~Raise proxy_buffer_size or fastcgi_buffer_size
primary script unknown~PHP-FPM cannot find the script nginx asked for~Compare root and SCRIPT_FILENAME in the site config
connect\(\) .*failed.*while connecting to upstream~The app behind the web server is down or not listening~Check the backend service and its port or socket
client intended to send too large body~An upload is bigger than client_max_body_size~Raise client_max_body_size for that site if the upload is legitimate
ssl_do_handshake\(\) failed~Clients failed the TLS handshake, usually scanners or very old clients~Ignore it unless real visitors complain
could not build.*hash~A hash table in the nginx config is too small~Follow the setting that nginx names in this line
reached maxrequestworkers|reached maxclients~Apache used all its workers, so visitors waited~Check MaxRequestWorkers with --tune
premature end of script headers~A CGI or PHP script died before it answered~Run the script by hand, or read the PHP log
client denied by server configuration~A Require rule blocked a request~Expected for private paths. Otherwise check the site config
script timed out~A script ran longer than the server allows~Find what the script waits for, usually the database
reached pm.max_children|max_children setting~PHP-FPM used all its workers, so requests waited~Check the pool with --tune, and look for slow scripts first
seems busy~PHP-FPM cannot keep up with incoming requests~Look for slow scripts, then check pm.max_children with --tune
execution timed out|request_terminate_timeout~A PHP script hit its time limit~Find what the script waits for, usually the database
allowed memory size.*exhausted~A PHP script hit memory_limit~Fix the script, or raise memory_limit for that site
exited on signal 11|sigsegv~A worker crashed~Update PHP and its extensions. Disable extensions one by one to find it
php fatal error~A PHP script stopped on an error~Read the file and line in the message
too many connections~The database refused clients at max_connections~Check it with --tune. Look for slow queries before raising it
too many clients|remaining connection slots~PostgreSQL refused clients at max_connections~Use a pooler such as PgBouncer, or check max_connections with --tune
out of shared memory~PostgreSQL ran out of lock or shared memory~Look at max_locks_per_transaction, and at long transactions
checkpoints are occurring too frequently~PostgreSQL writes more than its WAL settings allow~Raise max_wal_size
could not resize shared memory~The shared memory segment hit a limit~Check free space in /dev/shm, also inside containers
password authentication failed~A client logged in with the wrong password~Check the app config. Repeated from many addresses, it is an attack
deadlock (found|detected)~Two transactions blocked each other, and one was rolled back~The app should retry. Look at the order of its updates
aborted connection~A client disappeared without closing, or a timeout hit~Check max_allowed_packet, wait_timeout and app crashes
access denied for user~A client used a wrong user, password or host~Check the app config and the grants of that user
crashed and should be repaired~A MyISAM table is damaged~Back it up, then run REPAIR TABLE
table .* is full~A table or the temporary space reached its limit~Check free disk and tmp_table_size
got error 28~MySQL could not write, because the disk is full~Check free space on the data and tmp folders
log sequence number .* is in the future~InnoDB data and redo log disagree. This can mean damage~Back up first, then read the MySQL recovery documentation
can't save in background: fork|cannot allocate memory.*fork~Redis could not fork to save, so saves are failing~Set vm.overcommit_memory=1, or add memory
oom command not allowed~Redis reached maxmemory, so writes are refused~Check maxmemory and maxmemory-policy with --tune
max number of clients reached~Redis refused clients at maxclients~Look for leaking connections, then check maxclients with --tune
background saving error|rdb.*error~Saving to disk failed, so a restart would lose data~Check free disk and the owner of the data folder
fsync is taking too long~The disk is too slow for AOF~Check disk latency with iostat -x 1 3
memory overcommit must be enabled~A background save can fail under memory pressure~Set vm.overcommit_memory=1
wiredtiger error~The MongoDB storage engine reported an error~Check the disk, and read the full message
flood.stage disk watermark~The disk is nearly full, so indices became read-only~Free disk space. The block lifts by itself on recent versions
high disk watermark~The disk is filling, so shards move away from this node~Free disk space, or add a node
circuitbreakingexception|data too large~A request would have used too much heap~Reduce the request, or look at heap use with --tune
master not discovered~This node cannot find a cluster master~Check the network between nodes, and discovery settings
no server available|has no server available~A load balancer backend has no healthy server left~Check the backend servers and their health checks
server .* is down~A health check failed for one backend server~Check that server
child .* died|child .* not responding~The Varnish worker process crashed or hung~Read the panic text with varnishadm panic.show
could not get storage~Varnish ran out of cache storage~Check the malloc size with --tune
outofmemoryerror~The JVM ran out of heap~Check -Xmx and look for a memory leak
java.net.bindexception~The port this service wants is already taken~ss -lntp shows the owner
memory resource limit alarm|memory_high_watermark set~RabbitMQ hit its memory limit, so publishers are blocked~Consume the queues, then check the limit with --tune
disk free limit|disk_free_limit~RabbitMQ is short of disk, so publishers are blocked~Free disk space, or consume the queues
file descriptor limit~RabbitMQ is near its open file limit~Raise LimitNOFILE in its service unit
retry time not reached~Exim is waiting before it tries a host again~Normal for a host that is down. Check the queue with exim -bp
spool file is locked~Another Exim process is already delivering this message~Harmless unless it repeats for hours
unroutable address|unrouteable address~Exim has no route for this recipient~Check the address and the local domains list
sasl.*authentication failed~Someone failed to log in to SMTP~Repeated from many addresses, it is a password attack. Check fail2ban
does not resolve to address|hostname .* verification failed~The client's reverse DNS does not match~Normal for bots. Ignore it unless real mail is affected
mail for .* loops back to myself~Postfix thinks this domain is both local and remote~Check mydestination and the MX record
queue file write error~Postfix could not write to its queue~Check free disk space
database .* is older than source file~A postmap table is out of date~Run postmap on that file, then reload Postfix
mail_max_userip_connections|exceeded.*connections~One user has too many IMAP connections from one address~Raise mail_max_userip_connections, or fix the mail client
corrupted index~A Dovecot index file is damaged~Dovecot rebuilds it by itself. Repeated, check the disk
zone .* not loaded~BIND could not load a zone~Run named-checkzone on that zone
refused notify~BIND refused a NOTIFY from a server it does not trust~Check also-notify and allow-notify
network unreachable resolving~BIND tried a network this server does not have, usually IPv6~Harmless, or start named with -4
dnssec.*failed|no valid rrsig~A DNSSEC answer could not be validated~Check the zone with dnsviz, and the clock on this server
no space left on device~The disk is full~Open CPU, RAM and disk, then use the disk-full fix
disk quota exceeded~A quota is full~Check quotas for that user
too many open files~A program reached its open file limit~Raise LimitNOFILE in its service unit. --tune shows each program
cannot allocate memory|out of memory~The program could not get memory~Check RAM use and the limits with --tune
permission denied~A program may not read or write a file or socket~Compare the owner of that path with the user of the service
read-only file system~The disk went read-only, usually after errors~dmesg | tail -30
address already in use~The port this program wants is already taken~ss -lntup shows the owner
connection refused~Nothing is listening where this program connects~Check that the service it depends on runs
connection timed out|operation timed out~The other side did not answer in time~Check the network path and firewall
certificate.*(expired|verify failed)~A TLS certificate is not valid~Open Websites, domains and SSL
broken pipe|connection reset by peer~The other side closed the connection~Usually harmless. Look closer only if it is frequent
EOF
}

# Groups log lines from stdin. Prints the worst groups, then a line "@@@ lines groups".
err_group() {
    # The patterns go by environment: awk -v would eat their backslashes.
    { err_hints; printf '@@@DATA\n'; clean | tr '\200-\377' '?'; } | ERR_WANT=$1 ERR_SKIP=${2:-} awk -v limit="$ERR_SHOW" \
        -v sq="'" -v dim="$c_dim" -v off="$c_off" -v grn="$c_grn" '
        function mask(s,   low, pass, rs, rl, mid, cut, q, re) {
            q = "[\"" sq " ]*"
            re = "(pass(w(or)?d|phrase)?|pwd|secret|token|api[-_]?key|access[-_]?key|cookie)" q "[=:]" q "[^ ,;&\"" sq "*][^ ,;&\"" sq "]*"
            for (pass = 0; pass < 20; pass++) {
                low = tolower(s)
                if (!match(low, re)) break
                rs = RSTART; rl = RLENGTH
                mid = substr(s, rs, rl)
                cut = match(mid, /[=:]/)
                s = substr(s, 1, rs - 1) substr(mid, 1, cut) "***" substr(s, rs + rl)
            }
            for (pass = 0; pass < 20; pass++) {
                low = tolower(s)
                if (!match(low, /(bearer|basic) +[a-z0-9._~+\/=-][a-z0-9._~+\/=-]*/)) break
                rs = RSTART; rl = RLENGTH
                mid = substr(s, rs, rl)
                cut = index(mid, " ")
                s = substr(s, 1, rs + cut - 1) "***" substr(s, rs + rl)
            }
            for (pass = 0; pass < 20; pass++) {
                if (!match(s, /:\/\/[^:\/ ]+:[^@\/ ]+@/)) break
                s = substr(s, 1, RSTART + 2) "***@" substr(s, RSTART + RLENGTH)
            }
            return s
        }
        function norm(s) {
            s = tolower(s)
            sub(/, client: .*/, "", s)
            sub(/^\[[^]]*\] */, "", s)
            sub(/^[a-z][a-z][a-z] +[0-9]+ [0-9:]+ [^ ]+ /, "", s)
            gsub(/"[^"]*"/, "q", s)
            gsub(sq "[^" sq "]*" sq, "q", s)
            gsub(/[a-z0-9._+-]+@[a-z0-9.-]+/, "e", s)
            gsub(/\/[^ ,:;)]+/, "p", s)
            gsub(/0x[0-9a-f]+/, "h", s)
            gsub(/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]+/, "h", s)
            gsub(/[0-9]+/, "n", s)
            return substr(s, 1, 110)
        }
        BEGIN { hints = 1; want = ENVIRON["ERR_WANT"]; skip = ENVIRON["ERR_SKIP"] }
        hints {
            if ($0 == "@@@DATA") { hints = 0; next }
            if (split($0, h, "~") >= 3) { nh++; hp[nh] = h[1]; hc[nh] = h[2]; hx[nh] = h[3] }
            next
        }
        {
            low = tolower($0)
            if (low !~ want) next
            if (skip != "" && low ~ skip) next
            total++
            line = mask($0)
            k = norm(line)
            if (!(k in count)) { kinds++; key[kinds] = k }
            count[k]++
            sample[k] = line
        }
        END {
            for (shown = 0; shown < limit && shown < kinds; shown++) {
                best = 0
                for (i = 1; i <= kinds; i++)
                    if (!(key[i] in done) && (best == 0 || count[key[i]] > count[key[best]])) best = i
                k = key[best]; done[k] = 1
                printf "  %6dx  %s\n", count[k], substr(sample[k], 1, 150)
                low = tolower(sample[k])
                for (i = 1; i <= nh; i++) {
                    if (low ~ hp[i]) {
                        printf "           %sCause:%s %s\n           %sNext:%s %s%s%s\n", dim, off, hc[i], dim, off, grn, hx[i], off
                        break
                    }
                }
            }
            if (kinds > limit) printf "  %sand %d more kinds of error%s\n", dim, kinds - limit, off
            printf "@@@ %d %d\n", total, kinds
        }'
}

# Prints one group, and the summary line stays out of the report.
err_show() {
    local out rest lines kinds
    out=$(err_group "$1" "${2:-}")
    rest=${out##*@@@ }
    out=${out%@@@ *}
    read -r lines kinds <<< "$rest"
    ((ERR_LINES_SEEN += ${lines:-0}))
    ((ERR_KINDS += ${kinds:-0}))
    if ((${lines:-0} == 0)); then printf '  No errors in what was read.\n'
    else printf '%s' "$out"
    fi
}

err_tail() { run_t 6 tail -c "$ERR_BYTES" "$1" 2>/dev/null | tail -n "$ERR_LINES"; }

# How old a log is, so old trouble does not read as new trouble.
err_age() {
    local stamp now
    stamp=$(stat -c %Y "$1" 2>/dev/null) || return 0
    now=$(date +%s)
    [[ $stamp =~ ^[0-9]+$ && $now =~ ^[0-9]+$ ]] || return 0
    ((now >= stamp)) || return 0
    printf ', last written %s ago' "$(human_age "$((now - stamp))")"
}

# The running application, or one whose service has failed: that is when its log matters most.
err_on() { [[ -n $(sig_list RUNNING "$1") ]] || grep -qE "^($2)\.service" <<< "$SVC_FAILED"; }

# err_app NAME UNITS WANT SKIP PATH...: newest readable files first, then the journal.
err_app() {
    local name=$1 unit_list=$2 want=$3 skip=$4 file unit data denied=0 used=0
    local -a found=()
    shift 4
    for file in "$@"; do
        # A log linked to stderr can be this report itself, so only plain paths count.
        [[ -n $file && -f $file ]] || continue
        case $file in *.gz|*.xz|*.bz2|*.zip|/dev/*) continue ;; esac
        if [[ ! -r $file ]]; then denied=1; continue; fi
        [[ -s $file ]] || continue
        found+=("$file")
    done
    ((ERR_APPS += 1))
    sub "$name"
    if ((${#found[@]})); then
        while IFS= read -r file; do
            [[ -n $file ]] || continue
            ((used < 2)) || break
            ((used += 1))
            printf '  %s%s%s%s\n' "$c_dim" "${file#"$LHA_ROOT"}" "$(err_age "$file")" "$c_off"
            data=$(err_tail "$file")
            err_show "$want" "$skip" <<< "$data"
        done <<< "$(ls -t -- "${found[@]}" 2>/dev/null)"
        return 0
    fi
    if has journalctl; then
        for unit in $unit_list; do
            [[ $active_units == *$'\n'"$unit.service "* ]] || continue
            printf '  %sjournal of %s%s\n' "$c_dim" "$unit" "$c_off"
            data=$(run_t 8 journalctl -u "$unit" -n "$ERR_LINES" --no-pager -q -o cat 2>/dev/null)
            err_show "$want" "$skip" <<< "$data"
            return 0
        done
    fi
    if ((denied)); then printf '  Its log needs root to read.\n'
    else printf '  No log file or journal was found for it here.\n'
    fi
}

# Paths written in a config file: first word is the directive, second is the path.
err_conf_path() {
    local key=$1
    shift
    awk -v k="$key" -v sq="'" 'tolower($1) == k && $2 ~ /\// {
        v = $2; gsub(/[;"]/, "", v); gsub(sq, "", v)
        if (v ~ /^\//) print v
    }' "$@" 2>/dev/null
}

err_mysql_log() {
    local client=mysql value
    has mysql || client=mariadb
    has "$client" || return 0
    value=$(run_t 5 "$client" --connect-timeout=3 -NBe 'SELECT @@log_error' 2>/dev/null | clean)
    [[ $value == /* ]] && printf '%s\n' "$value"
}

err_apps() {
    local R=$LHA_ROOT line
    local -a conf=()
    if err_on '^(Nginx|OpenResty|Tengine)' 'nginx|ea-nginx|openresty'; then
        while IFS= read -r line; do [[ -z $line ]] || conf+=("$R$line"); done <<< "$(err_conf_path error_log "$R"/etc/nginx/nginx.conf "$R"/etc/nginx/conf.d/*.conf "$R"/usr/local/nginx/conf/nginx.conf)"
        err_app Nginx 'nginx ea-nginx openresty' '\[(emerg|alert|crit|error)\]' '' "${conf[@]}" "$R"/var/log/nginx/error.log \
            "$R"/var/log/ea-nginx/error.log "$R"/usr/local/nginx/logs/error.log "$R"/www/wwwlogs/nginx_error.log "$R"/usr/local/openresty/nginx/logs/error.log
    fi
    if err_on '^Apache HTTP' 'apache2|httpd'; then
        err_app Apache 'apache2 httpd' '(:|\[)(emerg|alert|crit|error)\]' '' "$R"/var/log/apache2/error.log "$R"/var/log/apache2/error_log \
            "$R"/var/log/httpd/error_log "$R"/etc/apache2/logs/error_log "$R"/usr/local/apache/logs/error_log "$R"/www/wwwlogs/error_log
    fi
    if err_on '^(LiteSpeed server|OpenLiteSpeed)' 'lsws|lshttpd|openlitespeed'; then
        err_app LiteSpeed 'lsws lshttpd openlitespeed' '\[(error|crit|alert|emerg|fatal)\]' '' "$R"/usr/local/lsws/logs/error.log "$R"/usr/local/lsws/logs/stderr.log
    fi
    if err_on '^PHP-FPM' 'php[-0-9.]*fpm[0-9.]*|ea-php[0-9]*-php-fpm|plesk-php[0-9]*-fpm|alt-php[0-9]*-php-fpm'; then
        err_app PHP-FPM "$(awk '$1 ~ /php.*fpm/ { sub(/\.service$/, "", $1); print $1 }' <<< "$active_units" | tr '\n' ' ')" \
            '(warning|error|alert|emergency|fatal)[]: ]' '' "$R"/var/log/php*-fpm.log "$R"/var/log/php-fpm/error.log "$R"/var/log/php-fpm/www-error.log \
            "$R"/opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log "$R"/opt/cpanel/ea-php*/root/usr/var/log/php-fpm.log \
            "$R"/var/opt/remi/php*/log/php-fpm/error.log "$R"/www/server/php/*/var/log/php-fpm.log \
            "$R"/opt/plesk/php/*/var/log/php-fpm.log "$R"/var/log/plesk-php*-fpm/error.log
    fi
    if err_on '^(MariaDB server|MySQL-compatible)' 'mariadb|mysql|mysqld'; then
        conf=()
        line=$(err_mysql_log)
        [[ -z $line ]] || conf+=("$R$line")
        err_app 'MySQL or MariaDB' 'mariadb mysql mysqld' '\[(error|err|fatal)\]|too many connections|aborted connection|crashed|deadlock' '' "${conf[@]}" \
            "$R"/var/log/mysql/error.log "$R"/var/log/mysql/mysqld.log "$R"/var/log/mysqld.log "$R"/var/log/mariadb/mariadb.log \
            "$R"/var/lib/mysql/*.err "$R"/www/server/data/*.err
    fi
    if err_on '^PostgreSQL server' 'postgresql(@.*|-[0-9.]*)?'; then
        err_app PostgreSQL "$(awk '$1 ~ /^postgresql/ { sub(/\.service$/, "", $1); print $1 }' <<< "$active_units" | tr '\n' ' ')" \
            '(error|fatal|panic):|too frequently' '' "$R"/var/log/postgresql/*.log "$R"/var/lib/pgsql/*/data/log/*.log "$R"/var/lib/pgsql/data/log/*.log \
            "$R"/var/lib/pgsql/*/data/pg_log/*.log "$R"/var/lib/pgsql/data/pg_log/*.log "$R"/var/lib/postgresql/*/main/log/*.log "$R"/var/lib/postgresql/data/log/*.log
    fi
    if err_on '^Redis server' 'redis|redis-server'; then
        conf=()
        while IFS= read -r line; do [[ -z $line ]] || conf+=("$R$line"); done <<< "$(err_conf_path logfile "$R"/etc/redis/redis.conf "$R"/etc/redis.conf "$R"/etc/redis/*.conf)"
        err_app Redis 'redis-server redis' ' # |oom command|error' '' "${conf[@]}" "$R"/var/log/redis/redis-server.log "$R"/var/log/redis/redis.log "$R"/var/log/redis_*.log
    fi
    if err_on '^Valkey server' 'valkey|valkey-server'; then
        conf=()
        while IFS= read -r line; do [[ -z $line ]] || conf+=("$R$line"); done <<< "$(err_conf_path logfile "$R"/etc/valkey/valkey.conf "$R"/etc/valkey.conf)"
        err_app Valkey 'valkey-server valkey' ' # |oom command|error' '' "${conf[@]}" "$R"/var/log/valkey/valkey-server.log "$R"/var/log/valkey/valkey.log
    fi
    if err_on '^MongoDB' 'mongod|mongodb'; then
        conf=()
        while IFS= read -r line; do [[ -z $line ]] || conf+=("$R$line"); done <<< "$(err_conf_path path: "$R"/etc/mongod.conf)"
        err_app MongoDB 'mongod mongodb' '"s":"[ef]"| [ef]  [a-z]' '' "${conf[@]}" "$R"/var/log/mongodb/mongod.log "$R"/var/log/mongodb/mongodb.log
    fi
    if err_on '^Elasticsearch' 'elasticsearch'; then
        err_app Elasticsearch elasticsearch '\]\[(error|fatal|critical) *\]|outofmemory|watermark' '' "$R"/var/log/elasticsearch/*.log "$R"/usr/share/elasticsearch/logs/*.log
    fi
    if err_on '^OpenSearch' 'opensearch'; then
        err_app OpenSearch opensearch '\]\[(error|fatal|critical) *\]|outofmemory|watermark' '' "$R"/var/log/opensearch/*.log "$R"/usr/share/opensearch/logs/*.log
    fi
    if err_on '^HAProxy' 'haproxy'; then
        err_app HAProxy haproxy 'no server available|is down|has no server|\[alert\]|\[emerg\]' '' "$R"/var/log/haproxy.log "$R"/var/log/haproxy/*.log
    fi
    if err_on '^Varnish' 'varnish|varnishd'; then
        err_app Varnish 'varnish varnishd' 'panic|child .* (died|not responding)|could not|error' '' "$R"/var/log/varnish/varnishd.log
    fi
    if err_on '^Apache Tomcat' 'tomcat[0-9]*'; then
        err_app Tomcat "$(awk '$1 ~ /^tomcat/ { sub(/\.service$/, "", $1); print $1 }' <<< "$active_units" | tr '\n' ' ')" \
            'severe|outofmemory| error |exception' '' "$R"/var/log/tomcat*/catalina.out "$R"/var/log/tomcat*/catalina.*.log \
            "$R"/opt/tomcat/logs/catalina.out "$R"/opt/tomcat/logs/catalina.*.log "$R"/usr/local/tomcat/logs/catalina.*.log
    fi
    if err_on '^RabbitMQ' 'rabbitmq-server'; then
        err_app RabbitMQ rabbitmq-server '\[(error|critical)\]|error report|alarm' '' "$R"/var/log/rabbitmq/*.log
    fi
    if err_on '^Apache Kafka' 'kafka|confluent-kafka'; then
        err_app Kafka 'kafka confluent-kafka' ' (error|fatal) |outofmemory' '' "$R"/var/log/kafka/server.log "$R"/opt/kafka/logs/server.log
    fi
    if err_on '^ClickHouse' 'clickhouse-server'; then
        err_app ClickHouse clickhouse-server '<(error|fatal|critical)>' '' "$R"/var/log/clickhouse-server/clickhouse-server.err.log
    fi
    if err_on '^Apache Cassandra' 'cassandra'; then
        err_app Cassandra cassandra '^(error|fatal) |outofmemory' '' "$R"/var/log/cassandra/system.log
    fi
    if err_on '^Squid' 'squid'; then
        err_app Squid squid 'error|fatal|warning: (no|all)' '' "$R"/var/log/squid/cache.log
    fi
    if err_on '^Caddy' 'caddy'; then err_app Caddy caddy "$ERR_ANY" "$ERR_QUIET" "$R"/var/log/caddy/*.log; fi
    if err_on '^Traefik' 'traefik'; then err_app Traefik traefik "$ERR_ANY" "$ERR_QUIET" "$R"/var/log/traefik/traefik.log; fi
    if err_on '^InfluxDB' 'influxd|influxdb'; then err_app InfluxDB 'influxdb influxd' "$ERR_ANY" "$ERR_QUIET" "$R"/var/log/influxdb/influxd.log; fi
    if err_on '^MinIO' 'minio'; then err_app MinIO minio "$ERR_ANY" "$ERR_QUIET"; fi
    if err_on '^Keepalived' 'keepalived'; then err_app Keepalived keepalived "$ERR_ANY" "$ERR_QUIET"; fi
    if err_on '^GlusterFS' 'glusterd'; then err_app GlusterFS glusterd ' [ewac] \[' '' "$R"/var/log/glusterfs/glusterd.log; fi
    if err_on '^Ceph' 'ceph'; then err_app Ceph '' "$ERR_ANY" "$ERR_QUIET" "$R"/var/log/ceph/ceph.log "$R"/var/log/ceph/ceph-mgr*.log; fi
    if err_on '^Exim' 'exim|exim4'; then
        err_app Exim 'exim exim4' ' \*\* |panic|error|failed|frozen' 'rejected rcpt|retry timeout exceeded' \
            "$R"/var/log/exim_paniclog "$R"/var/log/exim/paniclog "$R"/var/log/exim4/paniclog \
            "$R"/var/log/exim_mainlog "$R"/var/log/exim/main.log "$R"/var/log/exim4/mainlog
    fi
    if err_on '^Postfix' 'postfix|postfix@-'; then
        err_app Postfix 'postfix postfix@-' 'postfix[-/a-z]*\[[0-9]+\]: (fatal|panic|error|warning):' '' "$R"/var/log/mail.log "$R"/var/log/maillog "$R"/var/log/mail/mail.log
    fi
    if err_on '^Dovecot' 'dovecot'; then
        err_app Dovecot dovecot '(error|fatal|panic): ' 'postfix' "$R"/var/log/dovecot.log "$R"/var/log/dovecot/dovecot.log "$R"/var/log/mail.err "$R"/var/log/maillog
    fi
    if err_on '^PowerDNS authoritative' 'pdns'; then
        err_app PowerDNS pdns 'error|fatal|exception|failed' '' "$R"/var/log/pdns.log
    fi
    if err_on '^PowerDNS Recursor' 'pdns-recursor'; then
        err_app 'PowerDNS Recursor' pdns-recursor 'error|fatal|exception|failed' '' "$R"/var/log/pdns_recursor.log
    fi
    if err_on '^BIND' 'named|bind9'; then
        err_app BIND 'named bind9' 'error|failed|not loaded|fatal|refused notify' 'query (cache )?denied' "$R"/var/log/named/*.log "$R"/var/log/bind/*.log "$R"/var/named/data/named.run
    fi
    if err_on '^cPanel' 'cpanel'; then
        err_app cPanel cpanel '\] (error|die|fatal) |\[(error|die|fatal)\]| error ' '' "$R"/usr/local/cpanel/logs/error_log
    fi
}

# Containers that are up or broken. docker logs reads what the engine already stored.
err_containers() {
    local i name image status shown engine
    for ((i = 0; i < CT_N; i++)); do
        engine=${CT_ENGINE[i]}
        [[ $engine != crictl ]] || continue
        shown=0
        while IFS='|' read -r name image status _; do
            [[ -n $name ]] || continue
            case $status in Exited\ \(0\)*|Exited\ \(143\)*|Created*) continue ;; esac
            ((shown < 12)) || break
            ((shown += 1))
            ((ERR_APPS += 1))
            sub "Container $name ($engine)"
            run_t 8 "$engine" logs --tail 300 "$name" 2>&1 | err_show "$ERR_ANY" "$ERR_QUIET"
        done <<< "${CT_ROWS[i]}"
    done
}

view_errors() {
    ERR_APPS=0 ERR_LINES_SEEN=0 ERR_KINDS=0
    title 'Errors from running applications' 'From a bounded tail of each log: grouped, counted, and explained where the error is a common one.'
    printf '  %sThis view shows real log lines, which can hold private data. Think before sharing it.%s\n' "$c_yel" "$c_off"
    printf '  %sThey appear only here, never in --report or --json. Passwords and tokens are masked, as far as a pattern can tell.%s\n' "$c_dim" "$c_off"
    if ((LHA_UID != 0)); then printf '  %sWithout root, many logs cannot be read.%s\n' "$c_dim" "$c_off"; fi
    err_apps
    err_containers
    if ((ERR_APPS == 0)); then
        printf '\n  No known application was found running here.\n'
    else
        printf '\n  %d error lines of %d kinds, in the last %d lines or %d MiB of each log.\n' "$ERR_LINES_SEEN" "$ERR_KINDS" "$ERR_LINES" "$((ERR_BYTES / 1048576))"
    fi
    tips_begin
    tip 'tail -f /var/log/nginx/error.log' 'watch one log live'
    tip 'journalctl -u NAME -p err -n 50' 'errors of one service'
    tip 'docker logs --tail 50 NAME' 'what a container printed last'
    tip 'grep -c "error" FILE' 'count lines in a whole log'
}

view_resources_full() {
    view_resources
    metric_inventory
}

view_inventory() { run_audit --found-only --inventory; }

# Terminal UI. Keys and report colors go through fd 9.
tui_open() {
    if [[ -z ${TERM:-} || $TERM == dumb ]] || ! { exec 9<>/dev/tty; } 2>/dev/null; then
        printf '%s\n' 'Interactive mode needs a terminal. Use --text for a plain report.' >&2
        return 1
    fi
    if [[ ${tui_inherited:-no} != yes ]]; then
        LHA_EXIT_CMD='printf "\033[0m\033[?25h\033[?1049l" >&9'
        trap "$LHA_EXIT_CMD" EXIT
        printf '\033[?1049h\033[?25l' >&9
    fi
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
}

tui_size() {
    local dimensions
    dimensions=$(stty size <&9 2>/dev/null) || dimensions=
    read -r term_rows term_cols <<< "$dimensions"
    [[ $term_rows =~ ^[1-9][0-9]*$ ]] || term_rows=24
    [[ $term_cols =~ ^[1-9][0-9]*$ ]] || term_cols=80
}

tui_style() {
    accent='' secondary='' dim='' bold='' reset='' selected='' green='' red='' magenta=''
    if [[ ! ${NO_COLOR+x} ]]; then
        accent=$'\033[96m' secondary=$'\033[93m' dim=$'\033[90m'
        green=$'\033[92m' red=$'\033[91m' magenta=$'\033[95m'
        bold=$'\033[1m' reset=$'\033[0m' selected=$'\033[7m'
    fi
}

tui_key() {
    local wait=$1 suffix
    key=
    if [[ -n $wait ]]; then
        IFS= read -rsn 1 -t "$wait" -u 9 key || return "$?"
    else
        IFS= read -rsn 1 -u 9 key || return "$?"
    fi
    if [[ $key == $'\e' ]]; then
        IFS= read -rsn 2 -t 0.05 -u 9 suffix || return 0
        case $suffix in
            '[A'|'OA') key=up ;;
            '[B'|'OB') key=down ;;
            *) key=unknown ;;
        esac
    fi
}

tui_rescan() {
    F_N=0 F_CRIT=0 F_WARN=0 F_INFO=0 checks_done=no tune_done=no
    run_checks
}

# Worst finding in the given areas: crit, warn or ok.
menu_state() {
    local i
    REPLY=ok
    for ((i = 0; i < F_N; i++)); do
        [[ ${F_AREA[i]} =~ ^($1)$ ]] || continue
        case ${F_SEV[i]} in
            CRIT) REPLY=crit; return 0 ;;
            WARN) REPLY=warn ;;
        esac
    done
}

# menu_add STATE LABEL BADGE HEADING ACTION. HEADING starts a new group above this item.
menu_add() {
    menu_states[menu_n]=$1 menu_labels[menu_n]=$2 menu_badges[menu_n]=${3:-} menu_heads[menu_n]=${4:-} menu_actions[menu_n]=${5:-}
    ((menu_n += 1))
}

# First screen: what do you want to do?
menu_page_main() {
    local count
    menu_state '.*'
    menu_add tool 'Monitor' 'see what this server is doing' 'WHAT DO YOU WANT TO DO?' page:monitor
    menu_add "$REPLY" 'Troubleshoot and debug' "$F_CRIT critical, $F_WARN warnings" '' page:debug
    menu_add tool 'Tune' 'how full each limit is, and advice' '' page:tune
    menu_add tool 'Full report on one page' '' 'MORE' view_report
    menu_add tool 'Learn: guided tour and glossary' '' '' view_learn
}

menu_page_monitor() {
    local i text
    menu_add tool 'Overview' 'what this server is, and its health' 'THE SERVER' view_overview
    menu_add tool 'Live monitor' 'CPU, RAM, disk, network charts' '' monitor
    menu_add tool 'Trends: last 24 hours' 'peaks and history' '' view_trends:day
    menu_add tool 'Trends: last 7 days' 'with a disk forecast' '' view_trends:week
    menu_add tool 'Trends: last 30 days' '' '' view_trends:month
    menu_state 'resources|disk'
    menu_add "$REPLY" 'CPU, RAM and disk' "CPU $R_CPU%, RAM $R_MEM_PCT%" '' view_resources_full

    text="$(awk 'NF { n++ } END { print n + 0 }' <<< "$SVC_APPS") services"
    menu_state services
    menu_add "$REPLY" 'Applications and services' "$text" 'WHAT RUNS HERE' view_apps
    if ((CT_N > 0)) || [[ -n $CT_PLATFORMS ]]; then
        text=
        for ((i = 0; i < CT_N; i++)); do text+="${CT_ENGINE[i]} ${CT_STATE[i]%%,*}  "; done
        menu_state containers
        menu_add "$REPLY" 'Docker and containers' "$text$CT_PLATFORMS" '' view_containers
    else
        menu_add none 'Docker and containers' 'not on this server' '' view_containers
    fi
    if [[ $K_API == yes ]]; then
        menu_state kubernetes
        menu_add "$REPLY" 'Kubernetes' "$K_READY/$K_NODES nodes, $K_BAD bad pods" '' view_kube
    elif [[ $K_ON == yes ]]; then
        menu_state kubernetes
        menu_add "$REPLY" 'Kubernetes' 'found, cluster not readable here' '' view_kube
    else
        menu_add none 'Kubernetes' 'not on this server' '' view_kube
    fi
    menu_state web
    menu_add "$REPLY" 'Websites, domains and SSL' "$W_CERT_N certificates" '' view_web
    menu_state data
    if [[ -n $DB_ROWS ]]; then menu_add "$REPLY" 'Databases and caches' '' '' view_data
    else menu_add none 'Databases and caches' 'none found' '' view_data
    fi
    menu_state network
    menu_add "$REPLY" 'Ports and network' "$NET_PUBLIC public ports" 'NETWORK' view_network
    menu_state jobs
    menu_add "$REPLY" 'Scheduled jobs, backups, monitoring' '' '' view_jobs
}

menu_page_debug() {
    local failed
    failed=$(awk 'NF { n++ } END { print n + 0 }' <<< "$SVC_FAILED")
    menu_state '.*'
    menu_add "$REPLY" 'Problems and what to do' "$F_CRIT critical, $F_WARN warnings" 'START HERE' view_problems
    menu_add tool 'Logs: why did something stop?' 'may show private data' '' view_logs
    menu_add tool 'Errors in application logs' 'grouped and explained, may show private data' '' view_errors
    menu_state services
    menu_add "$REPLY" 'Failed services' "$failed failed" 'LOOK CLOSER' view_apps
    menu_state 'resources|disk'
    menu_add "$REPLY" 'CPU, RAM and disk' "CPU $R_CPU%, RAM $R_MEM_PCT%" '' view_resources_full
    menu_state network
    menu_add "$REPLY" 'Ports, firewall and network' "$NET_PUBLIC public ports" '' view_network
    menu_state security
    menu_add "$REPLY" 'Security' '' '' view_security
    menu_add tool 'All installed software' '' '' view_inventory
    if declare -F fix_list >/dev/null; then
        menu_add tool 'Fix problems' 'cause, plan, confirmation, undo' 'FIX' page:fix
    fi
}

menu_page_tune() {
    local group advice state
    printf '\r\033[K  Reading limits...' >&9
    tune_collect
    menu_add tool 'All tuning on one page' "$(awk -F '|' 'NF && $6 != "" { n++ } END { print n + 0 }' <<< "$TUNE_ROWS") changes advised" 'OVERVIEW' view_tune
    menu_add tool 'Memory budget' 'all limits against the RAM of this server' '' view_budget
    local head='SERVICES ON THIS SERVER'
    while IFS= read -r group; do
        [[ -n $group ]] || continue
        advice=$(awk -F '|' -v g="$group" '$1 == g && $6 != "" { n++ } END { print n + 0 }' <<< "$TUNE_ROWS")
        state=ok
        ((advice == 0)) || state=warn
        menu_add "$state" "$group" "$advice changes advised" "$head" "view_tune_one:$group"
        head=''
    done <<< "$(tune_groups)"
    if declare -F fix_list >/dev/null; then
        menu_add tool 'Apply advice' 'test, backup, undo, one at a time' 'CHANGE' page:apply
    fi
}

tui_menu_items() {
    menu_n=0
    case $page in
        monitor) menu_title=Monitor; menu_page_monitor ;;
        debug) menu_title='Troubleshoot and debug'; menu_page_debug ;;
        tune) menu_title=Tune; menu_page_tune ;;
        main) menu_title=''; menu_page_main ;;
        *) "menu_page_$page" ;;
    esac
}

menu_frame() {
    local index text icon color line room count offset=0 selected_line=0 gap=no legend
    local width=$((term_cols - 10))
    local -a lines=()
    ((width >= 1)) || width=1
    ((term_rows < 31)) || gap=yes
    for ((index = 0; index < menu_n; index++)); do
        if [[ -n ${menu_heads[index]} ]]; then
            if [[ $gap == yes && $index != 0 ]]; then lines+=(''); fi
            lines+=(" $bold${menu_heads[index]}$reset")
        fi
        case ${menu_states[index]} in
            ok) icon=$g_ok color=$green ;;
            warn) icon=$g_warn color=$secondary ;;
            crit) icon=$g_crit color=$red ;;
            none) icon=$g_none color=$dim ;;
            *) icon=$g_tool color=$accent ;;
        esac
        printf -v text '%-36s' "${menu_labels[index]}"
        line=${menu_badges[index]}
        if ((width >= 36)); then line=${line:0:width-36}
        else text=${text:0:width} line=
        fi
        if ((index == choice)); then
            selected_line=${#lines[@]}
            lines+=("$selected > ${menu_keys:index:1}  $icon  $text$line$reset")
        else
            lines+=("   ${menu_keys:index:1}  $color$icon$reset  $text$dim$line$reset")
        fi
    done
    count=${#lines[@]}
    room=$((term_rows - 3))
    ((term_rows < 25)) || room=$((term_rows - 4))
    ((room >= 3)) || room=3
    if ((count > room)); then
        offset=$((selected_line - room / 2))
        ((offset >= 0)) || offset=0
        ((offset <= count - room)) || offset=$((count - room))
    fi
    printf '%s %.*s%s\n' "$bold$accent" "$((term_cols - 1))" "LINUX HOST AUDIT${menu_title:+  >  $menu_title}  ${H_NAME:-}" "$reset"
    printf ' %s\n' "$(verdict)"
    ((term_rows < 25)) || printf '\n'
    printf '%s\n' "${lines[@]:offset:room}"
    legend="$g_ok ok  $g_warn warning  $g_crit critical  $g_none not here  "
    if ((term_cols < 62)); then legend=; fi
    printf ' %s%s%s' "$dim" "$legend" "$reset"
    if [[ -n $menu_title ]]; then legend='q back'; else legend='q quit'; fi
    if ((count > room)); then printf '%sUp/Down scrolls  %s%s' "$dim" "$legend" "$reset"
    else printf '%sEnter open  r rescan  %s%s' "$dim" "$legend" "$reset"
    fi
}

tui_main() (
    local key choice=0 index frame term_rows term_cols accent secondary dim bold reset selected
    local tui_inherited=no tui_active=yes menu_keys=123456789abcdefghilmnoptuvwxyz page=main
    local menu_n=0 menu_title='' action
    local -a menu_states menu_labels menu_badges menu_heads menu_actions
    tui_open || return 1
    tui_style
    tui_glyphs
    LHA_COLOR=always
    ui_colors
    printf '\033[H\033[J\n  Reading this server. This takes a few seconds...\n\n' >&9
    run_checks
    tui_report view_overview
    while :; do
        tui_size
        tui_menu_items
        ((choice < menu_n)) || choice=0
        frame=$(menu_frame)
        tui_paint "$frame"
        tui_key '' || return 0
        case $key in
            up|k) choice=$(((choice+menu_n-1)%menu_n)); continue ;;
            down|j) choice=$(((choice+1)%menu_n)); continue ;;
            r|R)
                printf '\033[H\033[J\n  Reading this server again...\n\n' >&9
                tui_rescan
                continue ;;
            q|Q)
                [[ $page != main ]] || return 0
                page=main choice=0
                continue ;;
            '') ;;
            *)
                [[ -n $key && $menu_keys == *"$key"* ]] || continue
                index=${menu_keys%%"$key"*}
                ((${#index} < menu_n)) || continue
                choice=${#index} ;;
        esac
        action=${menu_actions[choice]}
        case $action in
            page:*) page=${action#page:} choice=0 ;;
            monitor) (tui_inherited=yes; monitor_main) ;;
            view_tune_one:*) tui_report view_tune_one "${action#*:}" ;;
            view_trends:*) tui_report view_trends "${action#*:}" ;;
            run:*) tui_direct "${action#run:}" ;;
            *) tui_report "$action" ;;
        esac
    done
)

# For actions that ask questions: no pager in the way, and a visible cursor.
tui_direct() {
    printf '\033[H\033[J\033[?25h' >&9
    local -a words
    read -r -a words <<< "$1"
    "${words[@]}" >&9 2>&1
    printf '\nPress Enter for the menu.\n' >&9
    IFS= read -r -u 9 || :
    printf '\033[?25l\033[H\033[J' >&9
    tui_rescan
}

tui_report() {
    local charset=ascii
    # With LC_ALL=C, less would show Unicode as <E2><96> unless told otherwise.
    [[ $glyph_mode != utf8 ]] || charset=utf-8
    printf '\033[H\033[J' >&9
    if has less; then
        ( "$@" ) 2>&1 | LESSCHARSET=$charset LESS= less -FRX '-PsSpace = next page, q = back to the menu' >&9
    else
        ( "$@" ) >&9 2>&1
    fi
    printf '\nPress Enter for the menu.\n' >&9
    IFS= read -r -u 9 || :
}

tui_rate() {
    local count=$1 divisor=1 unit='B/s'
    rate='--'
    (( count >= 0 )) || return 0
    if (( count >= 1073741824 )); then divisor=1073741824; unit='GiB/s'
    elif (( count >= 1048576 )); then divisor=1048576; unit='MiB/s'
    elif (( count >= 1024 )); then divisor=1024; unit='KiB/s'
    fi
    if (( divisor == 1 )); then
        printf -v rate '%d %s' "$count" "$unit"
    else
        printf -v rate '%d.%d %s' "$((count/divisor))" "$(((count%divisor)*10/divisor))" "$unit"
    fi
}

# Draw over the old frame instead of clearing first: a cleared screen is what flickers.
# The ?2026 pair asks terminals that support it to show the frame all at once.
tui_paint() {
    local frame=$1
    frame=${frame//$'\n'/$'\033[K\n'}
    printf '\033[?2026h\033[H%s\033[K\033[J\033[?2026l' "$frame" >&9
}

# Decide between Unicode and ASCII once. Asking the terminal is more reliable than the locale:
# after printing one 3-byte block, the cursor sits in column 2 only if it was drawn as one cell.
tui_glyphs() {
    local reply='' column=''
    if [[ -z ${glyph_mode:-} ]]; then
        printf '\r\xe2\x96\x88\033[6n' >&9
        IFS= read -rs -d R -t 1 -u 9 reply || :
        printf '\r\033[K' >&9
        [[ $reply != *';'* ]] || column=${reply##*;}
        if [[ $column == 2 ]]; then glyph_mode=utf8
        elif [[ -z $column && ${LHA_LOCALE:-} == *[Uu][Tt][Ff]* ]]; then glyph_mode=utf8
        else glyph_mode=ascii
        fi
    fi
    glyph_set
}

glyph_set() {
    if [[ $glyph_mode == utf8 ]]; then
        g_full=$'\xe2\x96\x88' g_empty=$'\xe2\x96\x91'
        g_h=$'\xe2\x94\x80' g_v=$'\xe2\x94\x82' g_tl=$'\xe2\x95\xad' g_tr=$'\xe2\x95\xae'
        g_bl=$'\xe2\x95\xb0' g_br=$'\xe2\x95\xaf'
        g_ok=$'\xe2\x97\x8f' g_warn=$'\xe2\x96\xb2' g_crit=$'\xe2\x96\xa0'
        g_none=$'\xe2\x97\x8b' g_tool=$'\xe2\x96\xba'
        blocks=(' ' $'\xe2\x96\x81' $'\xe2\x96\x82' $'\xe2\x96\x83' $'\xe2\x96\x84'
            $'\xe2\x96\x85' $'\xe2\x96\x86' $'\xe2\x96\x87' $'\xe2\x96\x88')
    else
        g_full='#' g_empty=' '
        g_h=- g_v='|' g_tl=+ g_tr=+ g_bl=+ g_br=+
        g_ok='*' g_warn='!' g_crit=X g_none=- g_tool='>'
        blocks=(' ' . . : : '=' '=' '#' '#')
    fi
}

chart_rule() {
    local count=$1
    REPLY=
    ((count > 0)) || return 0
    printf -v REPLY '%*s' "$count" ''
    REPLY=${REPLY// /$g_h}
}

# Top or bottom border carrying a left and a right label.
chart_border() {
    local corner_l=$1 corner_r=$2 inner=$3 left=$4 right=$5 room fill text
    if [[ -z $left ]]; then
        right=${right:0:inner-3}
        chart_rule "$((inner - ${#right} - 3))"
        fill=$REPLY
        chart_rule 1
        chart_rows+=("$dim$corner_l$fill$reset $dim$right$reset $dim$REPLY$corner_r$reset")
        return 0
    fi
    room=$((inner - ${#left} - 7))
    ((room >= 0)) || room=0
    right=${right:0:room}
    fill=$((inner - ${#left} - ${#right} - 6))
    chart_rule "$fill"
    fill=$REPLY
    if [[ -n $right ]]; then text=" $right "; else text=$g_h$g_h; fi
    chart_rule 1
    chart_rows+=("$dim$corner_l$REPLY$reset$bold$accent ${left:0:inner-4} $reset$dim$fill$reset$text$dim$REPLY$corner_r$reset")
}

# Adds one series from the series array as an area chart: newest sample on the right,
# eight levels per text row. A style of "heat" colors rows by how high they are.
chart_area() {
    local height=$1 inner=$2 limit=$3 style=$4
    local units=$((height * 8)) start=$((${#series[@]} - inner)) col idx value row base step line color
    local -a level
    ((height > 0)) || return 0
    for ((col = 0; col < inner; col++)); do
        idx=$((start + col))
        value=-1
        ((idx < 0)) || value=${series[idx]:--1}
        level[col]=0
        if ((value > 0)); then
            level[col]=$(((value * units + limit - 1) / limit))
            ((level[col] <= units)) || level[col]=$units
        fi
    done
    for ((row = height - 1; row >= 0; row--)); do
        base=$((row * 8)) line=''
        for ((col = 0; col < inner; col++)); do
            step=$((level[col] - base))
            if ((step <= 0)); then line+=' '
            elif ((step >= 8)); then line+=${blocks[8]}
            else line+=${blocks[step]}
            fi
        done
        color=$style
        if [[ $style == heat ]]; then
            step=$(((row + 1) * 100 / height))
            if ((step > 85)); then color=$red
            elif ((step > 60)); then color=$secondary
            else color=$green
            fi
        fi
        chart_rows+=("$dim$g_v$reset$color$line$reset$dim$g_v$reset")
    done
}

# Rate charts scale to their own recent peak, with a floor so an idle server stays flat.
chart_peak() {
    local value
    peak=65536
    for value in "${series[@]}"; do ((value <= peak)) || peak=$value; done
}

# chart_build leaves a finished box in chart_rows: height rows plus two borders.
chart_build() {
    local pane=$1 width=$2 height=$3 inner=$(($2 - 2)) title value left right low peak rate
    local peak_a peak_b upper short
    local -a series
    chart_rows=()
    case $pane in
        cpu|ram)
            if [[ $pane == cpu ]]; then title=CPU value=$cpu_pct series=("${cpu_history[@]}")
            else title=RAM value=$ram_pct series=("${ram_history[@]}")
            fi
            if ((value < 0)); then value=--; else value+=%; fi
            chart_border "$g_tl" "$g_tr" "$inner" "$title" "$value"
            chart_area "$height" "$inner" 100 heat
            chart_border "$g_bl" "$g_br" "$inner" '' '0-100%'
            ;;
        disk|net)
            upper=$(((height + 1) / 2))
            if [[ $pane == disk ]]; then
                title=DISK left=read right=write low=$disk_write
                tui_rate "$disk_read"; value=$rate
            else
                title=NETWORK left=in right=out low=$net_tx
                tui_rate "$net_rx"; value=$rate
            fi
            short=$value
            tui_rate "$low"
            value="$left $value  $right $rate"
            # Never cut a number in half: narrow panes drop the words instead.
            ((${#value} <= inner - ${#title} - 7)) || value="$short / $rate"
            ((${#value} <= inner - ${#title} - 7)) || title=
            chart_border "$g_tl" "$g_tr" "$inner" "$title" "$value"
            if [[ $pane == disk ]]; then series=("${disk_r_history[@]}"); else series=("${net_r_history[@]}"); fi
            chart_peak
            peak_a=$peak
            chart_area "$upper" "$inner" "$peak_a" "$accent"
            if [[ $pane == disk ]]; then series=("${disk_w_history[@]}"); else series=("${net_t_history[@]}"); fi
            chart_peak
            peak_b=$peak
            chart_area "$((height - upper))" "$inner" "$peak_b" "$magenta"
            tui_rate "$peak_a"
            value="peak $rate / "
            tui_rate "$peak_b"
            chart_border "$g_bl" "$g_br" "$inner" '' "$value$rate"
            ;;
    esac
}

chart_pair() {
    local first=$1 second=$2 index
    local -a left_chart chart_rows
    chart_build "$first" "$pane_width" "$chart_height"
    left_chart=("${chart_rows[@]}")
    chart_build "$second" "$pane_width" "$chart_height"
    for ((index = 0; index < ${#left_chart[@]}; index++)); do
        printf ' %s %s\n' "${left_chart[index]}" "${chart_rows[index]}"
    done
}

monitor_frame() {
    local term_rows term_cols width pane_width chart_height pane line text procs=0
    local -a chart_rows
    tui_size
    ((term_rows < 36)) || procs=7
    width=$term_cols
    ((width <= 170)) || width=170
    printf ' %s%s%s  %s%s%s\n' "$bold$accent" 'LIVE SERVER MONITOR' "$reset" "$dim" "${H_NAME:-}  $activity" "$reset"
    if ((term_cols >= 60 && term_rows >= 14)); then
        pane_width=$(((width - 3) / 2))
        chart_height=$(((term_rows - 8 - procs) / 2))
        ((chart_height <= 16)) || chart_height=16
        chart_pair cpu ram
        chart_pair disk net
    elif ((term_cols >= 24 && term_rows >= 17)); then
        pane_width=$((width - 2))
        chart_height=$(((term_rows - 13) / 4))
        for pane in cpu ram disk net; do
            chart_build "$pane" "$pane_width" "$chart_height"
            for line in "${chart_rows[@]}"; do printf ' %s\n' "$line"; done
        done
    else
        printf ' CPU %s%%  RAM %s%%\n Make the window larger to see charts.\n' "$cpu_pct" "$ram_pct"
    fi
    if ((procs > 0)) && [[ -n $top_list ]]; then
        printf ' %s%6s %6s  %-12s %s%s\n' "$bold" 'CPU%' 'MEM%' USER PROCESS "$reset"
        printf '%s\n' "$top_list" | awk -v w="$((width - 1))" '{ printf " %6s %6s  %-12.12s %s\n", $1, $2, $3, $4 }'
    fi
    text="Load $load_now   Busiest: ${top_now:-unknown}"
    printf ' %.*s\n' "$((width - 1))" "$text"
    text="Disk: ${metrics_disk_scope:-unknown}   Network: ${metrics_net_scope:-unknown}"
    printf ' %s%.*s%s\n' "$dim" "$((width - 1))" "$text" "$reset"
    printf ' %.*s' "$((width - 1))" 'q Back   Space Pause'
}

monitor_main() (
    local key activity=LIVE paused=no rc frame accent secondary dim bold reset selected
    local cpu_pct=-1 ram_pct=-1 disk_read=-1 disk_write=-1 net_rx=-1 net_tx=-1
    local metrics_disk_scope metrics_net_scope load_now top_now top_list
    local -a cpu_history=() ram_history=() disk_r_history=() disk_w_history=() net_r_history=() net_t_history=()
    tui_open || return 1
    tui_style
    tui_glyphs
    while :; do
        if [[ $paused == no ]]; then
            metrics_snapshot
            load_now=$(cut -d ' ' -f 1-3 /proc/loadavg 2>/dev/null)
            top_list=$(ps -eo pcpu=,pmem=,user=,comm= --sort=-pcpu 2>/dev/null | head -n 5 | clean)
            top_now=$(awk 'NR == 1 { print $4, $1 "%" }' <<< "$top_list")
            if (( ${#cpu_history[@]} >= 180 )); then
                cpu_history=("${cpu_history[@]:1}"); ram_history=("${ram_history[@]:1}")
                disk_r_history=("${disk_r_history[@]:1}"); disk_w_history=("${disk_w_history[@]:1}")
                net_r_history=("${net_r_history[@]:1}"); net_t_history=("${net_t_history[@]:1}")
            fi
            cpu_history+=("$cpu_pct"); ram_history+=("$ram_pct")
            disk_r_history+=("$disk_read"); disk_w_history+=("$disk_write")
            net_r_history+=("$net_rx"); net_t_history+=("$net_tx")
        fi
        frame=$(monitor_frame)
        tui_paint "$frame"
        rc=0
        tui_key 1 || rc=$?
        (( rc != 1 )) || return 0
        case $key in
            q|Q) return 0 ;;
            ' ')
                if [[ $paused == yes ]]; then
                    # Reset rate baselines without plotting the paused interval.
                    metrics_snapshot
                    paused=no activity=LIVE
                else paused=yes activity=PAUSED
                fi
                ;;
        esac
    done
)

usage() {
    cat <<'EOF'
Linux Host Audit: understand any Linux server with one command. Read-only.

  bash linux-host-audit.sh              Overview first, then an interactive menu.
                                        Without a terminal it prints the full report.
Views (each prints and exits):
  --overview     What this server is, health, what runs, what is exposed
  --problems     Everything wrong, why it matters, and what to look at next
  --apps         Applications and services
  --network      Ports, firewall, routes
  --containers   Docker, Podman, LXD, Incus, Proxmox, libvirt (also: --docker)
  --k8s          Kubernetes: k8s, k3s, k0s, RKE2, MicroK8s, OpenShift
  --web          Websites, domains, SSL certificates
  --db           Databases and caches
  --security     SSH, firewall, users, updates
  --logs         Crashes, reboots, why services stopped (may show private data)
  --errors       Error logs of every running application, grouped, counted and explained
                 (shows real log lines, so it may show private data)
  --jobs         Cron, timers, backups, monitoring
  --resources    CPU, RAM, disk, top processes
  --tune         How full each database and web server limit is, with advice from real load
  --trends [day|week|month]  Recorded history, peaks and a disk forecast
  --learn        Guided tour and glossary
  --report       All of the above
  --json         Findings and server facts for scripts, with stable finding ids
Tools:
  --menu         Open the interactive menu
  --monitor      Live CPU, RAM, disk and network charts
  --check        One status line for cron or monitoring. Exit 0 OK, 1 warning, 2 critical
  --metrics      Raw kernel counters
  --text [--found-only] [--inventory] [--journal] [--all-services]
                 Software signature audit
  --version      Print the version

Run as root for the complete picture. NO_COLOR=1 turns colors off.
EOF
}

# Almost every check parses text with awk. Some minimal images do not ship it.
need_awk() {
    has awk && return 0
    if has busybox && busybox awk 'BEGIN { exit 0 }' 2>/dev/null; then
        awk() { busybox awk "$@"; }
        return 0
    fi
    printf 'This tool needs awk, which this system does not have.\n' >&2
    printf 'Install it first, for example: apt-get install gawk, dnf install gawk or zypper install gawk\n' >&2
    return 3
}

one_view() {
    ui_colors
    run_checks
    "$@"
}

main() {
    LHA_LOCALE=${LC_ALL:-${LC_CTYPE:-${LANG:-}}}
    export LC_ALL=C
    PATH=${LHA_TEST_PATH:+$LHA_TEST_PATH:}/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    PATH+=:/snap/bin:/var/lib/snapd/snap/bin:/var/lib/rancher/rke2/bin:/opt/bin:/run/current-system/sw/bin:/usr/local/apache2/bin
    export PATH
    # Path patterns are deliberately expanded. Field lists split on whitespace only.
    IFS=$' \t\n'
    set +f
    LHA_UID=${LHA_TEST_UID:-$EUID}
    # Here-strings can need a temp file, and /tmp may be the very disk that is full.
    if [[ -d /dev/shm && -w /dev/shm ]]; then export TMPDIR=/dev/shm; fi
    ui_colors

    case ${1:-} in
        --help|-h) usage; return 0 ;;
        --version) printf 'linux-host-audit %s\n' "$LHA_VERSION"; return 0 ;;
    esac
    if [[ $(uname -s) != Linux && -z ${LHA_TEST_PATH:-} ]]; then
        printf 'This tool requires Linux.\n' >&2
        return 1
    fi
    need_awk || return 3
    case ${1:-} in
        --trends) ;;
        --menu|--monitor|--metrics|--overview|--problems|--apps|--network|--containers|--docker|--k8s|\
        --web|--db|--security|--logs|--errors|--jobs|--resources|--tune|--learn|--report|--check|--json)
            if (($# != 1)); then printf 'Unexpected arguments for %s\n' "$1" >&2; return 2; fi ;;
    esac
    case ${1:-} in
        --menu) tui_main ;;
        --monitor) monitor_main ;;
        --metrics) metric_inventory ;;
        --overview) one_view view_overview ;;
        --problems) one_view view_problems ;;
        --apps) one_view view_apps ;;
        --network) one_view view_network ;;
        --containers|--docker) one_view view_containers ;;
        --k8s) one_view view_kube ;;
        --web) one_view view_web ;;
        --db) one_view view_data ;;
        --security) one_view view_security ;;
        --logs) one_view view_logs ;;
        --errors) one_view view_errors ;;
        --jobs) one_view view_jobs ;;
        --resources) one_view view_resources ;;
        --tune) one_view view_tune ;;
        --trends) ui_colors; view_trends "${2:-week}" ;;
        --learn) one_view view_learn ;;
        --report) one_view view_report ;;
        --json) NO_COLOR=1 one_view view_json ;;
        --check)
            NO_COLOR=1 ui_colors
            run_checks
            printf '%s: %s\n' "${H_NAME:-host}" "$(verdict)"
            if ((F_CRIT > 0)); then return 2; elif ((F_WARN > 0)); then return 1; fi ;;
        --text) shift; ui_colors; run_audit "$@" ;;
        '')
            if [[ -t 1 && -n ${TERM:-} && $TERM != dumb ]] && { : </dev/tty; } 2>/dev/null; then
                tui_main
            else
                one_view view_report
            fi
            ;;
        --found-only|--inventory|--journal|--all-services) ui_colors; run_audit "$@" ;;
        *) printf 'Unknown argument: %s\nTry --help\n' "$1" >&2; return 2 ;;
    esac
}

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
        FX_STEPS=('Check that UDP port 123 can leave this server.' 'timedatectl timesync-status' 'chronyc sources')
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
    local pool ram=$((R_MEM_TOTAL * 1024)) client=mysql
    has mysql || client=mariadb
    has "$client" || return 0
    pool=$(run_t 5 "$client" --connect-timeout=3 -NBe 'SELECT @@innodb_buffer_pool_size' 2>/dev/null)
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
    FX_STEPS+=('Lower PHP-FPM pm.max_children if PHP is the top user.' 'free -h' 'ps aux --sort=-rss | head')
    if fx_swap_possible; then fx_swap_plan; FX_CAUSE+=' This server has no swap.'; fi
}
ap_memory_low() { fx_swap_apply; }
ck_memory_low() { fx_swap_check; }
dx_oom_kills() {
    FX_CAUSE="Killed: ${1:-unknown}. Biggest users now: $(fx_top_memory 4)."
    fx_mysql_advice
    FX_STEPS+=('If php-fpm is a big user, lower pm.max_children, per pool or in your panel.'
        'journalctl -k | grep -i "out of memory"' 'Add RAM if the numbers above already look reasonable.')
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
        php*-fpm*) out=$(fx_phpfpm_test "$unit") || FX_CONFIG_ERROR=$out ;;
        # postconf only reads. "postfix check" creates missing folders and changes owners.
        postfix*) if has postconf; then
                out=$(run_t 10 postconf -n 2>&1 >/dev/null)
                [[ $out != *fatal* ]] || FX_CONFIG_ERROR=$out
            fi ;;
        named*|bind9*) has named-checkconf && out=$(run_t 10 named-checkconf 2>&1) || FX_CONFIG_ERROR=$out ;;
    esac
    FX_CONFIG_ERROR=$(printf '%s' "$FX_CONFIG_ERROR" | clean | grep -v 'syntax is ok\|test is successful' | tail -n 2 | tr '\n' ' ' | cut -c1-200)
}

# The binary of a PHP version: unit php8.2-fpm runs php-fpm8.2.
fx_phpfpm_bin() {
    local unit=${1%.service} version=''
    [[ $unit =~ ^php([0-9.]+)-fpm$ ]] && version=${BASH_REMATCH[1]}
    if [[ -n $version ]] && has "php-fpm$version"; then printf 'php-fpm%s' "$version"
    elif has php-fpm; then printf 'php-fpm'
    fi
}
fx_phpfpm_test() {
    local bin
    bin=$(fx_phpfpm_bin "$1")
    [[ -n $bin ]] || return 0
    run_t 10 "$bin" -t 2>&1
}

# Which package owns a file. Rpm is asked only where it has a database: see rpm_usable.
fx_owner_package() {
    if has dpkg; then dpkg -S "$1" 2>/dev/null | cut -d: -f1
    elif rpm_usable; then rpm -qf "$1" 2>/dev/null
    fi
}

fx_unit_log() { run_t 8 journalctl -u "$1" -n 60 --no-pager -q -o cat 2>/dev/null | clean; }

dx_service_failed() {
    local unit=${1:-} result status log port owner path pkg last enabled
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
            port=$(grep -i 'already in use' <<< "$log" | grep -oE ':[0-9]{2,5}' | tail -n 1 | tr -d :)
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
                pkg=$(fx_owner_package "$path")
                FX_STEPS=("ls -l $path" "Reinstall its package${pkg:+: $pkg}.")
                return 0
            fi ;;
    esac
    # The last lines are systemd's own summary. The reason is in what the program said before them.
    last=$(grep -vE '^(Failed to start|Started |Starting |Stopped |Stopping )|Main process exited|Failed with result|Unit entered|Control process exited|Scheduled restart|Start request repeated|\.service:[0-9]+: ' <<< "$log" | tail -n 1 | cut -c1-130)
    FX_CAUSE="It stopped with result ${result:-unknown}, exit status ${status:-unknown}. ${last:+Its last message: $last}"

    # A one-shot task is a job, not a daemon. Running it again repeats whatever it does.
    # RemainAfterExit marks jobs too: rc-local on RHEL is Type=forking, and it reruns boot commands.
    if [[ $(run_t 3 systemctl show -p Type --value -- "$unit" 2>/dev/null) == oneshot ||
          $(run_t 3 systemctl show -p RemainAfterExit --value -- "$unit" 2>/dev/null) == yes ||
          $unit == rc-local.service ]]; then
        FX_MODE=never
        FX_CAUSE+=' It is a one-shot task, and running it again would repeat its work.'
        FX_STEPS=("Read what it does first: systemctl cat $unit" "${FX_STEPS[@]}"
            "If the failure is old and harmless, clear the mark: systemctl reset-failed $unit")
        return 0
    fi
    # Not enabled at boot usually means somebody turned it off, so starting it changes the server.
    enabled=$(run_t 3 systemctl is-enabled "$unit" 2>/dev/null)
    if [[ $enabled != enabled ]]; then
        FX_MODE=never
        FX_CAUSE+=" It is not enabled at boot ($enabled), so it may be off on purpose."
        FX_STEPS=("If you want it on: systemctl enable --now $unit" "If not, clear the old failure: systemctl reset-failed $unit")
        return 0
    fi
    FX_MODE=auto FX_RISK=medium
    FX_PLAN=("Clear its failed state and start it once: systemctl start $unit")
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
dx_redis_down() {
    if [[ ${1:-} == Valkey ]]; then fx_delegate "$(fx_first_unit valkey valkey-server)"
    else fx_delegate "$(fx_first_unit redis redis-server valkey valkey-server)"
    fi
}
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
# Security fixes. Anything that could lock you out runs under the dead-man timer.

fx_ssh_port() { awk '$5 == "sshd" || $5 == "ssh" { print $2; exit }' <<< "$NET_ROWS"; }

fx_public_ports() { awk '$3 == "public" { print $2 "/" $1 }' <<< "$NET_ROWS" | sort -u; }

# A firewall also closes what listens on a private address, such as a database for the app
# server next door, so that has to stay open too. Only local listeners do not matter.
fx_open_ports() { awk '$3 != "local" { print $2 "/" $1 }' <<< "$NET_ROWS" | sort -u; }

fx_remote_clients() {
    run_t 5 ss -Htn state established "( sport = :$1 )" 2>/dev/null |
        awk '{ print $NF }' | grep -v '^127\.\|^\[::1\]' | sed 's/:[0-9]*$//' | sort -u | head -n 5 | tr '\n' ' '
}

dx_no_firewall() {
    local ssh count
    ssh=$(fx_ssh_port)
    count=$(fx_public_ports | wc -l | tr -d ' ')
    FX_CAUSE="No firewall is filtering traffic, so all $count public ports are reachable."
    if [[ -d /usr/local/cpanel ]]; then
        FX_MODE=never
        FX_STEPS=('cPanel needs many ports. Use WHM > Security Center, or install CSF, which knows them.')
        return 0
    fi
    if [[ -z $ssh ]]; then
        FX_MODE=never FX_CAUSE+=' The SSH port could not be found, so a firewall could lock you out.'
        return 0
    fi
    if has ufw; then FX_TOOL=ufw
    elif has firewall-cmd; then FX_TOOL=firewalld
    else
        FX_STEPS=('Install ufw (Debian, Ubuntu) or firewalld (RHEL family), then run this fix again.')
        return 0
    fi
    FX_MODE=auto FX_RISK=high FX_LOCKOUT=yes
    FX_PLAN=("Turn on $FX_TOOL." "Allow every port other machines can reach today, SSH ($ssh) first, so nothing changes for working services."
        'New ports will be closed from now on.' 'Then close the ports you do not want one by one.')
}
ap_no_firewall() {
    local port ssh
    ssh=$(fx_ssh_port)
    if [[ $FX_TOOL == ufw ]]; then
        fx_undo 'ufw --force disable'
        fx_run ufw allow "$ssh/tcp" || return 1
        while read -r port; do [[ -z $port ]] || fx_run ufw allow "$port" || return 1; done <<< "$(fx_open_ports)"
        fx_run ufw --force enable
    else
        fx_undo 'systemctl disable --now firewalld'
        fx_run systemctl enable --now firewalld || return 1
        fx_run firewall-cmd --permanent --add-port="$ssh/tcp" || return 1
        while read -r port; do [[ -z $port ]] || fx_run firewall-cmd --permanent --add-port="$port" || return 1; done <<< "$(fx_open_ports)"
        fx_run firewall-cmd --reload
    fi
}
ck_no_firewall() {
    if [[ $FX_TOOL == ufw ]]; then [[ $(ufw status 2>/dev/null) == *'Status: active'* ]]
    else [[ $(firewall-cmd --state 2>/dev/null) == running ]]
    fi
}

dx_ssh_root_password() {
    local keys=/root/.ssh/authorized_keys
    FX_CAUSE='Root can log in with only a password, the main target of SSH bots.'
    if [[ ! -s $keys ]] || ! grep -qE '^[^#]*(ssh-|ecdsa-|sk-)' "$keys"; then
        FX_MODE=never
        FX_CAUSE+=' Root has no SSH key, so turning passwords off would lock you out.'
        FX_STEPS=('Add your key first: ssh-copy-id root@THIS_SERVER' 'Check that the key logs in, then run this fix again.')
        return 0
    fi
    FX_MODE=auto FX_RISK=high FX_LOCKOUT=yes
    FX_PLAN=('Set PermitRootLogin prohibit-password. Root keeps logging in with its key.'
        'Test the SSH config before loading it. Reload keeps open sessions.')
}
ap_ssh_root_password() {
    local unit=sshd file=/etc/ssh/sshd_config
    [[ $(run_t 3 systemctl is-active ssh 2>/dev/null) != active ]] || unit=ssh
    # Undo runs newest first, and the reload has to come after the file is back.
    fx_quote systemctl reload "$unit"
    fx_undo "$REPLY"
    if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' "$file"; then
        # First match wins in sshd_config.d, so sort this file early.
        printf 'PermitRootLogin prohibit-password\n' | fx_write /etc/ssh/sshd_config.d/00-linux-host-audit.conf || return 1
    else
        { sed -E 's/^[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin prohibit-password/' "$file"
          grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]' "$file" || printf 'PermitRootLogin prohibit-password\n'; } | fx_write "$file" || return 1
    fi
    sshd -t || return 1
    fx_run systemctl reload "$unit"
}
# sshd -T prints the old name of this setting on many versions.
ck_ssh_root_password() {
    case $(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2 }') in
        prohibit-password|without-password) return 0 ;;
    esac
    return 1
}

dx_empty_passwords() {
    local names
    names=$(awk -F: '$2 == "" { printf "%s ", $1 }' /etc/shadow 2>/dev/null | clean)
    FX_CAUSE="These accounts have no password: ${names:-none}."
    [[ -n $names ]] || return 0
    FX_MODE=auto FX_RISK=medium
    FX_PLAN=("Lock them: passwd -l. SSH keys keep working unless the account is expired.")
}
ap_empty_passwords() {
    local name
    for name in $(awk -F: '$2 == "" { print $1 }' /etc/shadow); do
        fx_quote passwd -d "$name"
        fx_undo "$REPLY"
        fx_run passwd -l "$name" || return 1
    done
}
ck_empty_passwords() { ! awk -F: '$2 == "" { found = 1 } END { exit !found }' /etc/shadow; }

# Blocks one port from outside, and leaves this machine's own access working.
fx_block_plan() {
    local port=$1 label=$2 clients
    # Silence from a missing tool must not count as "nobody is connected".
    if ! has ss || ! run_t 5 ss -Htn state established >/dev/null 2>&1; then
        FX_STEPS=("Cannot tell who uses port $port on this system, so it stays open." "Check clients by hand, then block port $port.")
        return 0
    fi
    clients=$(fx_remote_clients "$port")
    if [[ -n $clients ]]; then
        FX_CAUSE+=" Remote clients are connected right now: $clients"
        FX_STEPS=('Do not close it until those clients move. Then limit access to their addresses.' "ss -tn '( sport = :$port )'")
        return 0
    fi
    if ! has iptables; then
        FX_STEPS=("Set the service to listen on 127.0.0.1, or block port $port in your firewall.")
        return 0
    fi
    FX_MODE=auto FX_RISK=medium FX_PORT=$port
    FX_PLAN=("Block port $port from outside. Nothing is connected to it from another machine now." "Local apps keep using $label.")
    FX_STEPS=("This rule disappears at reboot. For good, make $label listen on 127.0.0.1 only.")
}
# By interface: a local app that connects to this machine's own address arrives from that
# address, not from 127.0.0.1. A service on :: is open over IPv6 as well.
fx_block_apply() {
    local tool
    for tool in iptables ip6tables; do
        has "$tool" || continue
        [[ $tool == iptables || -d /proc/sys/net/ipv6 ]] || continue
        fx_quote "$tool" -D INPUT -p tcp --dport "$FX_PORT" '!' -i lo -j DROP
        fx_undo "$REPLY"
        fx_run "$tool" -I INPUT -p tcp --dport "$FX_PORT" '!' -i lo -j DROP || return 1
    done
}
fx_block_check() { iptables -S INPUT 2>/dev/null | grep -q -- "--dport $FX_PORT .*-j DROP"; }

dx_docker_api_open() {
    FX_CAUSE='The Docker API listens without TLS. Whoever reaches it has root here.'
    fx_block_plan 2375 Docker
    FX_STEPS+=('Remove tcp://0.0.0.0:2375 from dockerd options or daemon.json, then restart Docker in a quiet moment.')
}
ap_docker_api_open() { fx_block_apply; }
ck_docker_api_open() { fx_block_check; }
dx_db_exposed() {
    port_name "$1"
    FX_CAUSE="$REPLY listens on all interfaces, and no firewall was seen."
    fx_block_plan "$1" "$REPLY"
}
ap_db_exposed() { fx_block_apply; }
ck_db_exposed() { fx_block_check; }
dx_redis_open() {
    local port
    if [[ ${1:-} == Valkey ]]; then port=$(port_of valkey-server); else port=$(port_of redis-server); fi
    FX_CAUSE="$1 has no password and is public. Anyone can read it, or use it to take over the server."
    fx_block_plan "${port:-6379}" "$1"
    FX_STEPS+=('Then set bind 127.0.0.1 and requirepass in its config.')
}
ap_redis_open() { fx_block_apply; }
ck_redis_open() { fx_block_check; }

dx_updates_security() {
    local list hold
    FX_STEPS=('apt list --upgradable')
    if ! has apt-get; then
        FX_CAUSE='Security updates are waiting.'
        FX_STEPS=('dnf updateinfo list security' 'dnf upgrade --security')
        return 0
    fi
    list=$(run_t 15 apt-get -s -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade 2>/dev/null |
        awk '/^Inst .*[Ss]ecurity/ { print $2 }')
    # Databases, engines and kernels restart with real consequences, so a person picks the moment.
    hold=$(grep -E '^(mysql|mariadb|percona|postgresql|redis|valkey|mongodb|docker|containerd|kube|k3s|linux-)' <<< "$list" | tr '\n' ' ')
    FX_PACKAGES=$(grep -vE '^(mysql|mariadb|percona|postgresql|redis|valkey|mongodb|docker|containerd|kube|k3s|linux-)' <<< "$list" | tr '\n' ' ')
    FX_CAUSE="Waiting: $(tr '\n' ' ' <<< "$list" | cut -c1-160)"
    [[ -z $hold ]] || FX_STEPS+=("Update these at a planned moment, they restart key services: $hold")
    if [[ -n ${FX_PACKAGES// /} ]]; then
        FX_MODE=auto FX_RISK=medium FX_UNDOABLE=no
        FX_PLAN=("Install security updates: $FX_PACKAGES" 'Keep your existing config files.' 'Services that restart are checked afterwards.')
    fi
}
ap_updates_security() {
    # A timeout would kill dpkg in the middle of a package, and that is what breaks a server.
    # shellcheck disable=SC2086 # package names are split on purpose
    FX_TIMEOUT=3600 fx_run env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get -y -o Dpkg::Options::=--force-confold \
        install --only-upgrade $FX_PACKAGES
}
ck_updates_security() {
    local left name
    left=$(run_t 15 apt-get -s -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade 2>/dev/null)
    for name in $FX_PACKAGES; do
        [[ $left != *"Inst $name "* ]] || return 1
    done
}
# Containers and Kubernetes. Reads logs and states, and restarts only what is already broken.

fx_engine() {
    FX_ENGINE=docker
    has docker || FX_ENGINE=podman
}

# Last lines a container printed. They can hold private data, so they stay on this screen.
fx_ct_logs() { run_t 8 "$FX_ENGINE" logs --tail "${2:-6}" "$1" 2>&1 | clean | cut -c1-140; }

fx_ct_reason() {
    local name=$1 log lower
    log=$(fx_ct_logs "$name" 12)
    lower=$(tr 'A-Z' 'a-z' <<< "$log")
    case $lower in
        *'no space left'*) FX_CAUSE+=' The logs say the disk is full.' ;;
        *'address already in use'*) FX_CAUSE+=' A port it needs is already taken.' ;;
        *'permission denied'*) FX_CAUSE+=' A file or volume has the wrong owner.' ;;
        *'connection refused'*|*'could not connect'*|*'name or service not known'*|*'temporary failure in name'*)
            FX_CAUSE+=' It cannot reach something it depends on, such as its database.' ;;
        *'out of memory'*|*'cannot allocate'*) FX_CAUSE+=' It ran out of memory.' ;;
        *'no such file'*|*'not found'*) FX_CAUSE+=' A file or command it needs is missing, often a bad image or mount.' ;;
        *'password'*|*'authentication failed'*|*'access denied'*) FX_CAUSE+=' Its credentials are being rejected.' ;;
    esac
    FX_STEPS+=("Last log line: $(tail -n 1 <<< "$log")" "$FX_ENGINE logs --tail 100 $name")
}

dx_container_unhealthy() {
    local name=$1 probe
    fx_engine
    probe=$(run_t 5 "$FX_ENGINE" inspect -f '{{range .State.Health.Log}}{{.ExitCode}} {{end}}' "$name" 2>/dev/null)
    FX_CAUSE="Its health check keeps failing (recent exit codes: ${probe:-unknown})."
    fx_ct_reason "$name"
    FX_MODE=auto FX_RISK=medium FX_UNDOABLE=no FX_EXPECT_GONE="container $name"
    FX_PLAN=("Restart container $name once. Its data volumes stay.")
}
ap_container_unhealthy() { fx_run "$FX_ENGINE" restart "$1"; }
ck_container_unhealthy() {
    local i state
    for ((i = 0; i < 12; i++)); do
        state=$(run_t 5 "$FX_ENGINE" inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)
        [[ $state != healthy ]] || return 0
        sleep 5
    done
    return 1
}

# A restart cannot help these: the same thing happens again, so explain it precisely.
dx_container_restarting() {
    fx_engine
    FX_CAUSE='It crashes right after every start.'
    fx_ct_reason "$1"
}
dx_container_exit_error() {
    fx_engine
    FX_CAUSE="The program inside exited with an error."
    fx_ct_reason "$1"
    FX_STEPS+=("Start it again only after fixing the cause: $FX_ENGINE start $1")
}
dx_container_killed() {
    local oom
    fx_engine
    oom=$(run_t 5 "$FX_ENGINE" inspect -f '{{.State.OOMKilled}}' "$1" 2>/dev/null)
    if [[ $oom == true ]]; then FX_CAUSE='It was killed for using too much memory.'
    else FX_CAUSE='It was force-stopped (SIGKILL), not by the memory limit. Often docker stop timing out, or a person.'
    fi
    FX_STEPS=("$FX_ENGINE inspect -f '{{.HostConfig.Memory}}' $1" "$FX_ENGINE start $1")
}
dx_container_oom() {
    local limit
    fx_engine
    limit=$(run_t 5 "$FX_ENGINE" inspect -f '{{.HostConfig.Memory}}' "$1" 2>/dev/null)
    if [[ $limit == 0 ]]; then FX_CAUSE='No memory limit is set, so the host itself ran out of memory.'
    else FX_CAUSE="It reached its limit of $(fx_bytes "$limit")."
    fi
    FX_STEPS=("$FX_ENGINE stats --no-stream $1" "Raise its limit in compose or: $FX_ENGINE update --memory 1g --memory-swap 2g $1")
}
dx_container_restart_count() {
    fx_engine
    FX_CAUSE='It runs now, but it has crashed many times.'
    fx_ct_reason "$1"
}
dx_container_dead() {
    fx_engine
    FX_CAUSE='Docker could not stop or remove it. Often a stuck mount or storage trouble.'
    FX_STEPS=("$FX_ENGINE inspect $1" 'journalctl -u docker -n 50' "Check the volume is unused, then: $FX_ENGINE rm $1")
}
dx_container_privileged() {
    fx_engine
    FX_CAUSE='Privileged mode gives it almost full control of the host.'
    FX_MODE=never
    FX_STEPS=('Some tools need this. Find out which capability it needs, then use --cap-add instead.' "$FX_ENGINE inspect -f '{{.HostConfig.CapAdd}}' $1")
}

dx_container_log_large() {
    fx_engine
    FX_LOG_FILE=$(ls -S /var/lib/docker/containers/*/*-json.log 2>/dev/null | head -n 1)
    FX_CAUSE="Biggest log: ${FX_LOG_FILE:-not found}. Docker does not rotate logs by default."
    FX_STEPS=('Stop it coming back: set "log-opts": {"max-size": "100m", "max-file": "3"} in /etc/docker/daemon.json.' 'That applies to containers created afterwards.')
    [[ -n $FX_LOG_FILE ]] || return 0
    FX_MODE=auto FX_RISK=medium FX_UNDOABLE=no
    FX_PLAN=('Empty this log file. The container keeps running. Its old log lines are lost.')
    FX_SIZE_BEFORE=$(stat -c %s "$FX_LOG_FILE")
}
ap_container_log_large() { fx_run truncate -s 0 "$FX_LOG_FILE"; }
ck_container_log_large() { (($(stat -c %s "$FX_LOG_FILE") < FX_SIZE_BEFORE)); }

dx_engine_no_access() { FX_CAUSE='This user may not talk to the engine.'; FX_STEPS=('Run as root, or add the user to the docker group.'); }
dx_engine_hung() {
    FX_CAUSE='The engine does not answer. Usually storage trouble or a stuck container.'
    FX_STEPS=("journalctl -u $1 -n 50" 'dmesg | tail -30' "A restart stops containers without live-restore: systemctl restart $1")
}

# Kubernetes
fx_ku() { kube_find; ku "$@"; }

dx_kube_pods_unhealthy() {
    local line ns pod status reason
    FX_CAUSE='Each pod below says why it is not healthy.'
    FX_STEPS=()
    while read -r line; do
        [[ -n $line ]] || continue
        read -r ns pod _ status _ <<< "$line"
        case $status in
            CrashLoopBackOff) reason="crashes on start: kubectl logs $pod -n $ns --previous" ;;
            ImagePullBackOff|ErrImagePull) reason="image cannot be downloaded: check its name, tag and registry secret" ;;
            Pending) reason="no node can take it: kubectl describe pod $pod -n $ns, read Events" ;;
            OOMKilled) reason='out of memory: raise resources.limits.memory' ;;
            CreateContainerConfigError) reason='a secret or configmap it needs is missing' ;;
            Evicted) reason='the node ran short of resources' ;;
            *) reason="kubectl describe pod $pod -n $ns" ;;
        esac
        FX_STEPS+=("$ns/$pod $status: $reason")
    done <<< "$(head -n 12 <<< "$K_BAD_ROWS")"
}
dx_kube_node_notready() {
    local conditions
    conditions=$(fx_ku get node "$1" -o 'jsonpath={range .status.conditions[*]}{.type}={.status}: {.message}{"\n"}{end}' | clean | grep -v '=False' | head -n 3 | cut -c1-120)
    FX_CAUSE="Node conditions: ${conditions:-unknown}."
    FX_STEPS=("On that node: systemctl status kubelet" "journalctl -u kubelet -n 50 --no-pager" 'Also check its disk, memory and container runtime.')
    if [[ $1 == "$H_NAME" && $(run_t 3 systemctl is-active kubelet 2>/dev/null) != active ]]; then
        dx_service_failed kubelet.service
        FX_UNIT=kubelet.service
    fi
}
ap_kube_node_notready() { ap_service_failed "$FX_UNIT"; }
ck_kube_node_notready() { ck_service_failed "$FX_UNIT"; }
dx_kube_node_memory() { FX_CAUSE='The kubelet reports memory pressure, and will evict pods.'; FX_STEPS=("kubectl top pods -A --sort-by=memory" "kubectl describe node $1"); }
dx_kube_node_disk() { FX_CAUSE='The kubelet reports disk pressure, and will evict pods and remove images.'; FX_STEPS=('Run the disk fix on that node.' 'crictl rmi --prune'); }
dx_kube_deployments_unready() { FX_CAUSE='Deployments have fewer ready pods than requested.'; FX_STEPS=('kubectl get deploy -A' 'kubectl rollout status deploy/NAME -n NS' 'kubectl rollout undo deploy/NAME -n NS undoes a bad release.'); }
dx_kube_pvc_unbound() { FX_CAUSE='A storage claim has no volume.'; FX_STEPS=('kubectl get pvc -A' 'kubectl describe pvc NAME -n NS' 'kubectl get storageclass'); }
dx_kube_pods_restarting() { FX_CAUSE='These pods keep restarting.'; FX_STEPS=('kubectl logs POD -n NS --previous' 'kubectl get events -A --sort-by=.lastTimestamp | tail -20'); }
dx_kube_api_down() {
    FX_CAUSE='kubectl cannot reach the API server.'
    FX_STEPS=('systemctl status kubelet k3s rke2-server' 'crictl ps -a | grep -E "apiserver|etcd"' 'df -h /var/lib/etcd' 'kubeadm certs check-expiration')
}
dx_kube_cert_expiring() {
    FX_CAUSE="$1 expires within 30 days."
    FX_MODE=never
    FX_STEPS=('kubeadm: kubeadm certs renew all, then restart the control-plane static pods one at a time.' 'k3s or RKE2: restart the service, which rotates certificates near expiry.')
}
dx_kube_no_client() { FX_CAUSE='No kubectl on this machine.'; FX_STEPS=('crictl ps' 'Run this tool on a control-plane node.'); }
dx_kube_no_credentials() { FX_CAUSE='Normal on a worker node.'; FX_STEPS=('Run this tool on a control-plane node.'); }
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
    if [[ -n $(sig_list RUNNING '^Exim') ]]; then
        FX_STEPS=('exim -bp | exiqsumm | tail' 'exim -bp | head -20 shows sender addresses.')
    else
        FX_STEPS=('postqueue -p | tail shows the total.' 'postqueue -p | head -30 shows sender addresses.')
    fi
    FX_STEPS+=('If one account sends thousands, a site is hacked or a mailbox is stolen.')
}
dx_mysql_connections() { FX_CAUSE='Connections are close to max_connections.'; FX_STEPS=('SHOW FULL PROCESSLIST; look for slow queries first.' 'Raising the limit without that only uses more RAM.'); }
dx_postgres_connections() { FX_CAUSE='Connections are close to max_connections.'; FX_STEPS=('select state, count(*) from pg_stat_activity group by 1;' 'A connection pooler such as PgBouncer usually fixes this.'); }
dx_mysql_replication_stopped() { FX_MODE=never; FX_CAUSE='Replication stopped. Skipping an error can silently corrupt the replica.'; FX_STEPS=('SHOW REPLICA STATUS\G and read Last_Error. Before MySQL 8.0.22 and MariaDB 10.5: SHOW SLAVE STATUS\G' 'Fix the cause. Rebuild the replica if in doubt.'); }
dx_search_red() { FX_CAUSE='Some primary shards have no node.'; FX_STEPS=('curl -s localhost:9200/_cat/shards?v | grep UNASSIGNED' 'curl -s localhost:9200/_cluster/allocation/explain?pretty'); }

guide_fallback() {
    FX_CAUSE='No detailed diagnosis exists for this yet.'
    FX_STEPS=("See the Next command in the report for $1.")
}
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

fx_mysql_client() { FX_SQL=mysql; has mysql || FX_SQL=mariadb; }
fx_mysql_get() { run_t 6 "$FX_SQL" --connect-timeout=3 -NBe "SELECT @@GLOBAL.$1" 2>/dev/null; }

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
                max_connections|innodb_buffer_pool_size|tmp_table_size|table_open_cache|thread_cache_size|query_cache_type)
                    TA_KIND=mysql TA_DIR=$(tune_mysql_dir)
                    FX_MODE=auto FX_RISK=medium
                    FX_PLAN=("SET GLOBAL $TA_SETTING = $TA_RAW, with no restart.")
                    if [[ -n $TA_DIR ]]; then FX_PLAN+=("Save it in $TA_DIR/zz-linux-host-audit.cnf, so it survives a restart.")
                    else FX_PLAN+=('No included config folder was found, so this lasts until the next restart.')
                    fi ;;
                *) FX_STEPS+=("Under [mysqld] in your config, then a planned restart: $TA_SETTING = $TA_RAW") ;;
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
        Nginx*)
            if [[ -d /usr/local/cpanel ]]; then
                FX_STEPS+=('cPanel manages this nginx config. Use the WHM NGINX Manager or its settings file.')
            elif [[ $TA_SETTING == worker_connections || $TA_SETTING == worker_processes ]]; then
                TA_KIND=nginx FX_MODE=auto FX_RISK=medium TA_FILE=/etc/nginx/nginx.conf
                [[ -r $TA_FILE ]] || TA_FILE=/usr/local/nginx/conf/nginx.conf
                FX_PLAN=("Set $TA_SETTING $TA_RAW in $TA_FILE." 'Test with nginx -t, then reload. Open connections stay.')
            fi ;;
        'PHP-FPM pools')
            TA_POOL=${TA_SETTING%% *}
            TA_FILE=$(grep -lsE "^\[$TA_POOL\]" /etc/php-fpm.d/*.conf /etc/php/*/fpm/pool.d/*.conf /usr/local/etc/php-fpm.d/*.conf | head -n 1)
            if [[ -d /usr/local/cpanel ]]; then
                FX_STEPS+=('cPanel rebuilds these files. Change it in MultiPHP Manager > PHP-FPM Settings.')
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
            fx_quote "$FX_SQL" -e "SET GLOBAL $TA_SETTING = $old"
            fx_undo "$REPLY"
            fx_run "$FX_SQL" -e "SET GLOBAL $TA_SETTING = $TA_RAW" || return 1
            line=''
            # The smaller of these two is what counts, so they only ever move together.
            if [[ $TA_SETTING == tmp_table_size ]]; then
                old=$(fx_mysql_get max_heap_table_size)
                [[ -n $old ]] || return 1
                fx_quote "$FX_SQL" -e "SET GLOBAL max_heap_table_size = $old"
                fx_undo "$REPLY"
                fx_run "$FX_SQL" -e "SET GLOBAL max_heap_table_size = $TA_RAW" || return 1
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
                innodb_buffer_pool_size) ((value * 10 >= TA_RAW * 9 && value * 10 <= TA_RAW * 11)) ;;
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
        file=mysql
        has mysql || file=mariadb
        if has "$file"; then
            db=$(run_t 4 "$file" --connect-timeout=2 -NBe "SHOW GLOBAL STATUS LIKE 'Threads_connected'" 2>/dev/null | awk '{ print $2 + 0 }')
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
# Command line of the fixer.

fix_usage() {
    cat <<'EOF'
Linux Host Fix: finds the exact cause of each problem, and fixes what is safe to fix.

  bash linux-host-fix.sh                   Menus: monitor, troubleshoot and fix, tune and apply
  bash linux-host-fix.sh --list            Every problem, and how it can be handled
  bash linux-host-fix.sh --diagnose ID     Exact cause and plan. Changes nothing
  bash linux-host-fix.sh --dry-run         Diagnose everything. Changes nothing
  bash linux-host-fix.sh --fix ID[:TARGET] Fix one problem, after asking you
  bash linux-host-fix.sh --fix-all         Offer every automatic fix, one by one
  bash linux-host-fix.sh --tune            Tuning advice from real load, numbered
  bash linux-host-fix.sh --tune-apply N    Apply one piece of advice, after asking you
  bash linux-host-fix.sh --trends-on       Start recording history, a light sample every 5 minutes
  bash linux-host-fix.sh --trends-off      Stop recording, and keep the data
  bash linux-host-fix.sh --trends [week]   Show history: day, week or month
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
    local i count status worst=0 sev
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
            --dry-run) [[ $# -gt 1 ]] && FX_DRY=yes || words+=("$arg") ;;
            *) words+=("$arg") ;;
        esac
    done
    action=${words[0]:-} value=${words[1]:-}
    if [[ $(uname -s) != Linux && -z ${LHA_TEST_PATH:-} ]]; then fx_say 'This tool requires Linux.'; return 1; fi
    need_awk || return 3
    case $action in
        '')
            if [[ -t 1 && -n ${TERM:-} && $TERM != dumb ]] && { : </dev/tty; } 2>/dev/null; then tui_main
            else fix_usage
            fi ;;
        --help|-h) fix_usage ;;
        --record) trend_record ;;
        --trends) view_trends "${value:-week}" ;;
        --trends-on) run_checks; FX_SELF=$(readlink -f "$0" 2>/dev/null); fx_transaction trends-on '' ;;
        --trends-off) run_checks; fx_transaction trends-off '' ;;
        --tune) tune_list ;;
        --tune-apply) run_checks; fx_transaction tune-apply "$value" ;;
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

fix_main "$@"
