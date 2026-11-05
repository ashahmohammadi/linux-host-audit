#!/usr/bin/env bash
# Linux Host Audit: one command that explains a Linux server from zero to one hundred.
# Read-only: it changes nothing, installs nothing and sends nothing off the server.
# Never prints passwords, process arguments, container environments or Kubernetes secrets.
# Bash 3.2+ on any Linux. Missing tools only hide the part of the report that needs them.

LHA_VERSION=3.4.0

section() { title "$1"; }
has() { type -P "$1" >/dev/null 2>&1; }

package_snapshot() {
    if has dpkg-query && [[ -r /var/lib/dpkg/status ]]; then
        dpkg-query -W -f='${Status}\t${Package}\t${Version}\n' 2>/dev/null |
            awk -F '\t' '$1 ~ / ok installed$/ { print "dpkg:" $2, $3 }'
    fi
    # Without a system database, rpm creates a new one in the home folder.
    if has rpm && [[ -n $(ls /var/lib/rpm/Packages* /var/lib/rpm/rpmdb.sqlite \
        /usr/lib/sysimage/rpm/Packages* /usr/lib/sysimage/rpm/rpmdb.sqlite 2>/dev/null) ]]; then
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
            line=$0; sub(/^[[:space:]]+/, "", line)
            split(line,f,/[:[:space:]]+/)
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
detect 'PHP-FPM' 'php-fpm' '/etc/php/*/fpm/php-fpm.conf /etc/php-fpm.conf /opt/plesk/php/*/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /www/server/php/*/sbin/php-fpm' 'php-fpm php[0-9]*-fpm ea-php*-php-fpm alt-php*-fpm' 'php-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm'
detect 'LiteSpeed PHP (LSAPI)' 'lsphp' '/usr/local/lsws/lsphp*/bin/lsphp /opt/alt/php*/usr/bin/lsphp' 'lsphp[0-9][0-9] lsphp' 'lsphp'
detect 'Node.js' 'node nodejs' '' 'nodejs' 'node nodejs'
detect 'Python' 'python3 python' '' 'python3' ''
detect 'Gunicorn' 'gunicorn' '/etc/gunicorn.d' 'gunicorn gunicorn3' 'gunicorn'
detect 'uWSGI' 'uwsgi' '/etc/uwsgi' 'uwsgi' 'uwsgi'
detect 'Uvicorn' 'uvicorn' '' 'python3-uvicorn' 'uvicorn'
detect 'Java' 'java' '' '' ''
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
detect 'ClickHouse' 'clickhouse-server clickhouse' '/etc/clickhouse-server/config.xml' 'clickhouse-server' 'clickhouse-server'
detect 'InfluxDB' 'influxd' '/etc/influxdb/config.toml /etc/influxdb/influxdb.conf' 'influxdb influxdb2' 'influxd influxdb'
detect 'TimescaleDB' '' '' 'timescaledb-*' ''
detect 'MinIO object storage' 'minio' '/etc/default/minio' 'minio' 'minio'
detect 'Ceph storage' 'ceph' '/etc/ceph/ceph.conf' 'ceph ceph-common' 'ceph-mon ceph-osd ceph-mgr'
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
    local show_missing=yes inventory=no journal=no all_services=no unit ignored
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
        cache_directives 'NGINX FastCGI cache' '^[[:space:]]*fastcgi_cache[[:space:]]+[^[:space:]#;]+[[:space:]]*;' '^[[:space:]]*[a-z_]+[[:space:]]+off[[:space:]]*;' \
            /etc/nginx/nginx.conf /etc/nginx/{conf.d,sites-enabled,vhosts.d}/* \
            /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/{conf.d,vhost}/* \
            /www/server/panel/vhost/nginx/*.conf
        cache_directives 'NGINX proxy cache' '^[[:space:]]*proxy_cache[[:space:]]+[^[:space:]#;]+[[:space:]]*;' '^[[:space:]]*[a-z_]+[[:space:]]+off[[:space:]]*;' \
            /etc/nginx/nginx.conf /etc/nginx/{conf.d,sites-enabled,vhosts.d}/* \
            /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/{conf.d,vhost}/* \
            /www/server/panel/vhost/nginx/*.conf
        cache_directives 'Apache mod_cache' '^[[:space:]]*cacheenable[[:space:]]+(disk|socache|fd)[[:space:]]' '' \
            /etc/apache2/apache2.conf /etc/apache2/{conf-enabled,mods-enabled,sites-enabled}/* \
            /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf /usr/local/apache/conf/httpd.conf \
            /etc/apache2/conf/httpd.conf /www/server/panel/vhost/apache/*.conf
        cache_directives 'LiteSpeed cache rules' '^[[:space:]]*(cacheengine[[:space:]]+on([[:space:]#]|$)|enablecache[[:space:]]+1([[:space:]#]|$)|<enablecache>[[:space:]]*1[[:space:]]*</enablecache>)' '' \
            /usr/local/lsws/conf/httpd_config.{conf,xml} /usr/local/lsws/conf/vhosts/*/*.conf
        cache_directives 'PHP OPcache extension' '^[[:space:]]*zend_extension[[:space:]]*=[[:space:]]*[^;#]*opcache' '' \
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
        if has ss; then
            if ! ss -H -lntu 2>/dev/null; then printf 'Listener inventory unavailable\n'; fi
        elif has netstat; then
            if ! netstat -lntu 2>/dev/null; then printf 'Listener inventory unavailable\n'; fi
        else
            printf 'Listener inventory unavailable (ss and netstat missing)\n'
        fi
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
clean() { tr -d '\000-\010\013-\037\177'; }

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
    esac
    case $H_OS_ID:$H_OS_VERSION in
        ubuntu:14.04*) H_EOL=2019-04 ;;
        ubuntu:16.04*) H_EOL=2021-04 ;;
        ubuntu:18.04*) H_EOL=2023-05 ;;
        ubuntu:20.04*) H_EOL=2025-05 ;;
        ubuntu:22.04*) H_EOL=2027-04 ;;
        ubuntu:24.04*) H_EOL=2029-04 ;;
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
    if has zpool; then
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
    R_ZOMBIES=$(awk '$3 == "Z"' /proc/[0-9]*/stat 2>/dev/null | wc -l | tr -d ' ')
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
net_listeners() {
    local raw
    if has ss && raw=$(run_t 5 ss -lntup 2>/dev/null); then
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
        awk 'function hex(s,   i, v) {
                v = 0; s = tolower(s)
                for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1
                return v
            }
            FNR > 1 && $4 == "0A" {
                split($2, a, ":")
                ip = hex(substr(a[1], 7, 2)) "." hex(substr(a[1], 5, 2)) "." hex(substr(a[1], 3, 2)) "." hex(substr(a[1], 1, 2))
                print "tcp", hex(a[2]), ip, "?", "-"
            }' /proc/net/tcp 2>/dev/null
    fi
}

# NET_ROWS: proto port scope addr process pid, one row per proto/port/process.
net_collect() {
    NET_ROWS=$(net_listeners | awk '
        function scope(a) {
            sub(/%.*/, "", a); gsub(/[][]/, "", a)
            if (a ~ /^127\./ || a == "::1") return 1
            if (a ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|f[cd]|fe80)/) return 2
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
            6379|11211|27017|9200|2379|5900|5901|3306|5432|1433)
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
        MAIL_QUEUE=$(run_t 8 postqueue -p 2>/dev/null | awk '/^[0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]/ { n++ } END { print n + 0 }')
    fi
    [[ $MAIL_QUEUE =~ ^[0-9]+$ ]] || MAIL_QUEUE=
    if [[ -n $MAIL_QUEUE ]] && ((MAIL_QUEUE >= 1000)); then
        fid=mail-queue finding WARN services "$MAIL_QUEUE emails are stuck in the mail queue" \
            'Mail is not leaving, or a hacked site is sending spam.' 'exim -bp | head'
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
                        if (f[i] ~ /^[A-Za-z0-9*][-A-Za-z0-9.*]*\.[A-Za-z]{2,}$/ && f[i] !~ /^localhost/) print tolower(f[i])
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
    out=$(run_t 6 "$client" --connect-timeout=3 -e 'SHOW SLAVE STATUS\G' 2>/dev/null)
    if [[ -n $out ]]; then
        behind=$(awk '/Seconds_Behind_Master:/ { print $2 }' <<< "$out")
        db_row 'MySQL replica' "${behind:-?}s behind" "$(awk '/Slave_(IO|SQL)_Running:/ { printf "%s ", $0 }' <<< "$out" | tr -s ' ')"
        if [[ $out == *'Running: No'* ]]; then
            fid=mysql-replication-stopped finding CRIT data 'MySQL replication is stopped' 'This replica no longer receives data.' \
                "$client -e 'SHOW SLAVE STATUS\\G'"
        fi
    fi
}

check_postgres() {
    if ! has pg_isready; then db_row PostgreSQL "$1" 'pg_isready not available'; return 0; fi
    if ! run_t 5 pg_isready -t 3 >/dev/null 2>&1; then
        db_row PostgreSQL down 'pg_isready failed'
        fid=postgres-down finding CRIT data 'PostgreSQL is not answering' 'Apps using it will show database errors.' 'systemctl status postgresql'
        return 0
    fi
    db_row PostgreSQL running 'answers; details need the postgres user'
}

check_redis() {
    local name=$1 cli=$2 out role mem clients save
    has "$cli" || { db_row "$name" running 'no client to query it'; return 0; }
    out=$(run_t 5 "$cli" -h 127.0.0.1 ping 2>&1)
    case $out in
        *PONG*) ;;
        *NOAUTH*|*'Authentication required'*) db_row "$name" running 'password protected'; return 0 ;;
        *) db_row "$name" down 'no answer on 127.0.0.1:6379'
           fid=redis-down ftarget="$name" finding CRIT data "$name is not answering" 'Caches, sessions and queues using it will fail.' "$cli ping"
           return 0 ;;
    esac
    out=$(run_t 5 "$cli" -h 127.0.0.1 info 2>/dev/null | tr -d '\r')
    mem=$(awk -F: '$1 == "used_memory_human" { print $2 }' <<< "$out")
    clients=$(awk -F: '$1 == "connected_clients" { print $2 }' <<< "$out")
    role=$(awk -F: '$1 == "role" { print $2 }' <<< "$out")
    save=$(awk -F: '$1 == "rdb_last_bgsave_status" { print $2 }' <<< "$out")
    db_row "$name" running "$role, memory $mem, clients $clients"
    if [[ $save == err ]]; then
        fid=redis-save-failing ftarget="$name" finding CRIT data "$name cannot save to disk" 'A restart would lose recent data, and writes may be refused.' "$cli info persistence"
    fi
    if [[ $NET_ROWS == *"tcp 6379 public"* ]]; then
        fid=redis-open ftarget="$name" finding CRIT security "$name answers with no password on a public port" \
            'Anyone can read the data, and this is a well-known way to take over servers.' 'ss -lntp | grep 6379'
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
    )"
    for ((line = 0; line < CT_N; line++)); do
        out=$(printf '%s\n' "${CT_ROWS[line]}" | awk -F '|' 'tolower($2) ~ /(mysql|mariadb|postgres|redis|valkey|mongo|elastic|rabbitmq|clickhouse|kafka)/ {
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
check_security() {
    local out count value pid exe
    S_SSH= S_UPDATES=unknown S_FAILED=
    if has sshd && ((LHA_UID == 0)); then out=$(run_t 5 sshd -T 2>/dev/null); else out=; fi
    if [[ -z $out && -r /etc/ssh/sshd_config ]]; then
        out=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '!/^[ \t]*#/ && NF >= 2 && !s[tolower($1)]++ { print tolower($1), $2 }')
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
        value=$(ls /boot/vmlinuz-* 2>/dev/null | sed 's|.*/vmlinuz-||' | grep -v 'rescue\|debug' | sort -V 2>/dev/null | tail -n 1)
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
        fid=oom-kills ftarget="$victims" finding WARN resources "The kernel killed ${R_OOM:-some} processes for lack of memory since boot" \
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
            8.2) eol=2026-12 ;; 8.3) eol=2027-12 ;; 8.4) eol=2028-12 ;; *) eol= ;;
        esac
        app_row php "$version" "$eol"
    done <<< "$text"
    text=
    if has mariadb; then text=$(run_t 3 mariadb --version 2>/dev/null)
    elif has mysql; then text=$(run_t 3 mysql --version 2>/dev/null)
    fi
    if [[ -n $(sig_list RUNNING '^(MariaDB server|MySQL-compatible)') ]]; then
        version=$(sed -E 's/.*(Distrib|Ver) ([0-9]+\.[0-9]+).*/\2/' <<< "$text")
        if [[ $text == *MariaDB* ]]; then
            case $version in
                5.*|10.[0-2]) eol=2022-05 ;; 10.3) eol=2023-05 ;; 10.4) eol=2024-06 ;; 10.5) eol=2025-06 ;;
                10.6) eol=2026-07 ;; 10.11) eol=2028-02 ;; 11.4) eol=2029-05 ;; *) eol= ;;
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
            15) eol=2027-11 ;; 16) eol=2028-11 ;; 17) eol=2029-11 ;; *) eol= ;;
        esac
        app_row postgresql "$version" "$eol"
    fi
    if has node; then
        version=$(run_t 3 node --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/')
        if [[ $version =~ ^[0-9]+$ ]]; then
            case $version in
                ?|1[0-6]) eol=2023-09 ;; 17|18) eol=2025-04 ;; 19|20) eol=2026-04 ;; 21|22) eol=2027-04 ;;
                23|24) eol=2028-04 ;; *) eol= ;;
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
    [[ $mature == yes ]] || tune_note "$group" "Running for only $(human_age "$up"). Numbers are shown, but no advice until it has a full day of traffic."

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
            rec=$(tune_round "$(((total - free) * pool / total * 13 / 10))")
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

    if [[ $(tune_get "$vars" query_cache_type) == ON ]] && (($(tune_get "$vars" query_cache_size) > 0)); then
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
        rec=$(tune_round "$((rate > 4294967296 ? 4294967296 : rate))")
        why="$(tune_size "$rate") of redo log is written each hour. Too small a log causes write stalls."
    fi
    if ((size > 0)); then
        tune_row "$group" "$log_name" "$(tune_size "$((size * files))")" "$(tune_size "$rate") per hour" "$(tune_pct "$rate" "$((size * files))")" "${rec:+$(tune_size "$rec")}" "$why" 'restart' "$rec"
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
    out=$(run_t 8 setpriv --reuid=postgres --regid=postgres --clear-groups psql -w -AtF $'\t' -c "
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
        if ((now * 100 / max >= 85)); then rec=$((max * 3 / 2)) why='Near the limit. A pooler such as PgBouncer is usually better than a higher number.'; fi
    else
        tune_note "$group" 'Running for less than a day, so no advice yet.'
    fi
    tune_row "$group" max_connections "$max" "$now now" "$(tune_pct "$now" "$max")" "$rec" "$why" 'restart'
    rec='' why=''
    if (($(tune_get "$out" uptime) >= TUNE_MATURE)) && [[ $(awk -v h="$hit" 'BEGIN { print (h + 0 < 99) }') == 1 ]] && ((shared < ram / 4)); then
        rec=$(tune_round "$((ram / 4))") why="Only $hit% of reads come from memory, and the buffer is under a quarter of RAM."
    fi
    tune_row "$group" shared_buffers "$(tune_size "$shared")" "$hit% read hits" "$(tune_pct "$shared" "$ram")" "${rec:+$(tune_size "$rec")}" "$why" 'restart'
    work=$(($(tune_get "$out" work_mem) * 1024))
    temp=$(tune_get "$out" temp_files)
    tune_row "$group" work_mem "$(tune_size "$work")" "$temp temp files so far" 0 '' ''
    tune_budget PostgreSQL "$((shared + max * work))"
}

tune_redis() {
    local name=$1 cli=$2 info conf max used clients limit evicted hits misses frag rec why group version
    has "$cli" || return 0
    info=$(run_t 5 "$cli" -h 127.0.0.1 info 2>/dev/null | tr -d '\r' | tr ':' '\t')
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
    rec='' why=''
    if ((max == 0)); then
        rec=$(tune_round "$((used * 2))")
        why='No limit is set, so it can grow until the kernel kills something. Also pick a maxmemory-policy.'
    elif ((used * 100 / max >= 90 && evicted > 0)); then
        rec=$(tune_round "$((max * 3 / 2))") why="It is full, and has evicted $evicted keys."
    fi
    tune_row "$group" maxmemory "$( ((max == 0)) && printf unlimited || tune_size "$max")" "$(tune_size "$used") used" "$(tune_pct "$used" "$max")" "${rec:+$(tune_size "$rec")}" "$why" 'live' "$rec"
    conf=$(run_t 5 "$cli" -h 127.0.0.1 config get maxclients 2>/dev/null | tail -n 1 | tr -d '\r')
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
tune_connections() { run_t 5 ss -Htn state established "$1" 2>/dev/null | wc -l | tr -d ' '; }

tune_nginx() {
    local conf=/etc/nginx/nginx.conf procs conns cap wp wc rec why group nofile pid busy
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
    if [[ $wp =~ ^[0-9]+$ ]] && ((wp < H_CPUS && procs > 0 && busy / procs >= 50)); then
        rec=auto why="Workers average $((busy / procs))% CPU, and there are $H_CPUS cores."
    fi
    tune_row "$group" worker_processes "${wp:-1}" "$procs running" "$(tune_pct "$procs" "$H_CPUS")" "$rec" "$why" 'reload'
    conns=$(tune_connections '( sport = :80 or sport = :443 )')
    cap=$((procs * wc))
    rec='' why=''
    if ((cap > 0 && conns * 100 / cap >= 60)); then
        rec=$((wc * 2)) why="$conns open connections of $cap possible. A proxied request uses two."
    fi
    tune_row "$group" worker_connections "$wc" "$conns connections now" "$(tune_pct "$conns" "$cap")" "$rec" "$why" 'reload'
    # Workers carry worker_rlimit_nofile. The master keeps the limit it started with.
    pid=$(ps -eo pid=,args= 2>/dev/null | awk '$2 == "nginx:" && $3 == "worker" { print $1; exit }')
    if [[ $pid =~ ^[0-9]+$ ]]; then
        nofile=$(awk '/^Max open files/ { print $4 }' "/proc/$pid/limits" 2>/dev/null)
        if [[ $nofile =~ ^[0-9]+$ ]] && ((nofile < wc * 2)); then
            tune_row "$group" worker_rlimit_nofile "$nofile" 'open file limit' 0 "$((wc * 2))" 'Each connection needs a file handle, and a proxied one needs two.' 'reload'
        fi
    fi
}

tune_apache() {
    local bin mpm max threads procs conns reached file rec why group logs=0 real
    [[ -n $(sig_list RUNNING '^Apache HTTP') ]] || return 0
    if has httpd; then bin=httpd; else bin=apache2; fi
    has "$bin" || return 0
    group="Apache $(run_t 3 "$bin" -v 2>/dev/null | sed -n 's/.*Apache\/\([0-9.]*\).*/\1/p')"
    mpm=$(run_t 3 "$bin" -V 2>/dev/null | awk -F ': *' '/Server MPM/ { print tolower($2) }')
    max=$(cat /etc/apache2/conf/httpd.conf /etc/apache2/conf.d/*.conf /etc/httpd/conf/httpd.conf /etc/httpd/conf.modules.d/*.conf \
        /etc/apache2/mods-enabled/mpm_*.conf 2>/dev/null | awk 'tolower($1) ~ /^(maxrequestworkers|maxclients)$/ { v = $2 } END { print v }')
    threads=$(cat /etc/apache2/conf/httpd.conf /etc/httpd/conf/httpd.conf /etc/apache2/mods-enabled/mpm_*.conf 2>/dev/null |
        awk 'tolower($1) == "threadsperchild" { v = $2 } END { print v }')
    threads=${threads:-25}
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
    if ((${reached:-0} > 0)); then
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
    local pools workers logs line pool pm max count rss reached rec why total_run=0 shown=0 avg file real budget=0 measured=' ' pids
    [[ -n $(sig_list RUNNING '^PHP-FPM') ]] || return 0
    workers=$(ps -eo pid=,rss=,args= 2>/dev/null | awk '$3 == "php-fpm:" && $4 == "pool" { print }')
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
        if ((reached > 0 && max > 0)); then
            rec=$((max * 3 / 2))
            why="Its log shows the limit was hit $reached times. Each worker uses about $(human_kb "$rss")."
        fi
        tune_row 'PHP-FPM pools' "${pool:0:30} ($pm)" "$max" "$count workers, $(human_kb "$rss") each" "$(tune_pct "$count" "$max")" "$rec" "$why" 'reload'
        if [[ -z $rec ]] && ((max > 0 && count * 100 / max >= 90)); then
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
    local name=$1 row heap_pct heap_max ram_max disk rec why ver group
    [[ -n $(sig_list RUNNING "^$name") ]] && has curl || return 0
    ver=$(run_t 5 curl -s -m 3 http://127.0.0.1:9200/ 2>/dev/null | clean | sed -n 's/.*"number" *: *"\([0-9.]*\)".*/\1/p' | head -n 1)
    if [[ -z $ver ]]; then tune_note "$name" 'It needs a password, so its limits could not be read.'; return 0; fi
    group="$name $ver"
    while read -r row heap_pct heap_max ram_max disk; do
        [[ $heap_max =~ ^[0-9]+$ ]] || continue
        rec='' why=''
        if ((heap_max > 33285996544)); then rec=31g why='Above about 31 GiB, the JVM loses compressed pointers and gets less usable heap.'
        elif ((heap_max * 2 > ram_max + ram_max / 10)); then rec=$(tune_size "$((ram_max / 2))") why='Heap should leave half of RAM to the file cache.'
        elif ((heap_pct >= 85)); then rec=$(tune_size "$((heap_max * 3 / 2))") why="Heap is $heap_pct% full, so long garbage collection pauses are likely."
        fi
        tune_row "$group" "heap $row" "$(tune_size "$heap_max")" "$heap_pct% used" "$heap_pct" "$rec" "$why" 'restart'
        tune_row "$group" "disk $row" "$disk%" 'watermark at 85%' "${disk%%.*}" '' ''
        tune_budget "$name" "$heap_max"
    done <<< "$(run_t 5 curl -s -m 3 'http://127.0.0.1:9200/_cat/nodes?h=name,heap.percent,heap.max,ram.max,disk.used_percent&bytes=b' 2>/dev/null | clean)"
}

tune_mongo() {
    local client=mongosh out cache used conn avail ver group rec why
    [[ -n $(sig_list RUNNING '^MongoDB') ]] || return 0
    has mongosh || client=mongo
    has "$client" || return 0
    out=$(run_t 8 "$client" --quiet --eval 'var s = db.serverStatus(), c = s.wiredTiger.cache;
        print("version\t" + s.version); print("cache\t" + c["maximum bytes configured"]);
        print("used\t" + c["bytes currently in the cache"]); print("conn\t" + s.connections.current);
        print("avail\t" + s.connections.available);' 2>/dev/null | clean)
    if [[ -z $out || $out == *rror* ]]; then tune_note MongoDB 'It needs a login, so its limits could not be read.'; return 0; fi
    group="MongoDB $(tune_get "$out" version)"
    cache=$(tune_get "$out" cache)
    used=$(tune_get "$out" used)
    conn=$(tune_get "$out" conn)
    avail=$(tune_get "$out" avail)
    rec='' why=''
    if ((cache > 0 && used * 100 / cache >= 95)); then rec=$(tune_round "$((cache * 3 / 2))") why='The WiredTiger cache is full. Check it stays within RAM.'; fi
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
    rec='' why=''
    if ((max > 0 && now * 100 / max >= 80)); then rec=$((max * 3 / 2)) why="$now of $max connections are in use."; fi
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
    rec='' why=''
    if ((nuked > 0)); then rec=$(tune_round "$(((used + free) * 3 / 2))") why="$nuked objects were pushed out for lack of room."; fi
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

tune_tomcat() {
    local file threads pid busy heap group
    [[ -n $(sig_list RUNNING '^Apache Tomcat') ]] || return 0
    for file in /etc/tomcat*/server.xml /opt/tomcat/conf/server.xml /usr/local/tomcat/conf/server.xml; do
        [[ -r $file ]] && break
    done
    [[ -r ${file:-} ]] || return 0
    threads=$(grep -o 'maxThreads="[0-9]*"' "$file" | head -n 1 | tr -dc 0-9)
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
    read -r low high < /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null
    if [[ $low =~ ^[0-9]+$ ]] && has ss; then
        range=$((high - low))
        tw=$(run_t 5 ss -Htan state time-wait 2>/dev/null | wc -l | tr -d ' ')
        rec='' why=''
        if ((tw * 100 / range >= 70)); then rec='1024 65535' why='Outgoing ports are running out, which fails new connections to databases and backends.'; fi
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
        if ((pct >= 70)); then
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
        trap 'printf "\033[0m\033[?25h\033[?1049l" >&9' EXIT
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
    local tui_inherited=no tui_active=yes menu_keys=123456789abcdefghijklmnoptuvwxyz page=main
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
  --jobs         Cron, timers, backups, monitoring
  --resources    CPU, RAM, disk, top processes
  --tune         How full each database and web server limit is, with advice from real load
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
        --menu|--monitor|--metrics|--overview|--problems|--apps|--network|--containers|--docker|--k8s|\
        --web|--db|--security|--logs|--jobs|--resources|--tune|--learn|--report|--check|--json)
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
        --jobs) one_view view_jobs ;;
        --resources) one_view view_resources ;;
        --tune) one_view view_tune ;;
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

main "$@"
