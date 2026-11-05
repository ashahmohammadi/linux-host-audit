#!/bin/bash
# Runs the tuning view inside one real service container, and compares numbers with the service.
# The env argument can hold several settings, separated by a semicolon. A command is optional.
image=$1 env=$2 expect=$3 value=$4 command=$5 wait=${6:-30}
args=()
IFS=';' read -r -a settings <<< "$env"
for item in "${settings[@]}"; do args+=(-e "$item"); done
# shellcheck disable=SC2086 # a command is split on purpose
docker run -d --name svc "${args[@]}" "$image" $command >/dev/null || exit 1
sleep "$wait"
if [[ $(docker inspect -f '{{.State.Running}}' svc) != true ]]; then
    echo "FAIL: $image did not start. This is about the service, not the audit:"
    docker logs svc 2>&1 | tail -n 15
    exit 1
fi
docker cp linux-host-audit.sh svc:/tmp/audit.sh
docker exec -u 0 svc sh -c '
    if ! command -v bash >/dev/null || ! command -v awk >/dev/null || ! command -v ps >/dev/null || ! command -v curl >/dev/null; then
        if command -v microdnf >/dev/null; then microdnf install -y gawk procps-ng >/dev/null 2>&1
        elif command -v dnf >/dev/null; then dnf install -y gawk procps-ng >/dev/null 2>&1
        elif command -v yum >/dev/null; then yum install -y gawk procps-ng >/dev/null 2>&1
        elif command -v apt-get >/dev/null; then
            apt-get update -qq >/dev/null 2>&1
            for tool in gawk procps curl netcat-openbsd; do apt-get install -y -qq "$tool" >/dev/null 2>&1; done
        elif command -v apk >/dev/null; then apk add -q bash gawk procps curl >/dev/null 2>&1
        fi
    fi'
if ! docker exec svc sh -c 'command -v ps >/dev/null && command -v awk >/dev/null'; then echo 'NOTE: this image has no ps or no awk, and they could not be installed.'; fi
files() { docker exec -u 0 svc sh -c 'find /root /home -xdev -type f 2>/dev/null | sort'; }
before=$(files)
# Privileged, because root on a real host may read /proc/PID/fd, and a plain exec may not.
out=$(docker exec --privileged -u 0 -e MYSQL_PWD=t -e LHA_TUNE_MATURE=0 -e NO_COLOR=1 svc bash /tmp/audit.sh --tune 2>&1)
status=$?
printf '%s\n' "$out"
errors=$(docker exec --privileged -u 0 -e MYSQL_PWD=t -e NO_COLOR=1 svc bash /tmp/audit.sh --errors 2>&1)
errors_status=$?
printf '%s\n' "$errors" | tail -n 25
bad=0
[[ $status == 0 ]] || { echo "FAIL: exit $status"; bad=1; }
grep -qF "$expect" <<< "$out" || { echo "FAIL: missing $expect"; bad=1; }
grep -qF "$value" <<< "$out" || { echo "FAIL: missing $value"; bad=1; }
[[ $errors_status == 0 ]] || { echo "FAIL: --errors exit $errors_status"; bad=1; }
if grep -E 'command not found|syntax error|division by 0|bad substitution|arithmetic|invalid arithmetic' <<< "$out$errors"; then echo 'FAIL: shell error'; bad=1; fi
# The audit writes nothing, and client tools love to leave files in a home folder.
if [[ $(files) != "$before" ]]; then
    echo 'FAIL: files appeared in a home folder:'
    diff <(printf '%s\n' "$before") <(files) | head -n 10
    bad=1
fi

# The number on screen must be the number the service reports.
case $image in
    mariadb*|mysql*)
        client=$(docker exec svc sh -c 'command -v mariadb || command -v mysql')
        real=$(docker exec -e MYSQL_PWD=t svc "$client" -uroot -NBe 'select @@max_connections')
        grep -E "^  max_connections +$real " <<< "$out" || { echo "FAIL: max_connections is not $real"; bad=1; } ;;
    postgres*)
        real=$(docker exec -u postgres svc psql -Atc "select setting from pg_settings where name = 'max_connections'")
        grep -E "^  max_connections +$real " <<< "$out" || { echo "FAIL: max_connections is not $real"; bad=1; } ;;
    redis*|valkey*)
        real=$(docker exec svc sh -c 'cli=$(command -v redis-cli || command -v valkey-cli); $cli config get maxclients | tail -n 1')
        grep -E "^  maxclients +$real " <<< "$out" || { echo "FAIL: maxclients is not $real"; bad=1; } ;;
esac
docker rm -f svc >/dev/null
exit "$bad"
