#!/bin/bash
# Runs the tuning view inside one real service container, and compares numbers with the service.
image=$1 env=$2 expect=$3 value=$4
docker run -d --name svc -e "$env" "$image" >/dev/null || exit 1
sleep 30
docker cp linux-host-audit.sh svc:/tmp/audit.sh
docker exec svc sh -c '
    command -v bash >/dev/null || exit 9
    if ! command -v awk >/dev/null || ! command -v ps >/dev/null; then
        if command -v microdnf >/dev/null; then microdnf install -y gawk procps-ng >/dev/null 2>&1
        elif command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq gawk procps >/dev/null 2>&1
        fi
    fi'
out=$(docker exec -e MYSQL_PWD=t -e LHA_TUNE_MATURE=0 -e NO_COLOR=1 svc bash /tmp/audit.sh --tune 2>&1)
status=$?
printf '%s\n' "$out"
bad=0
[[ $status == 0 ]] || { echo "FAIL: exit $status"; bad=1; }
grep -qF "$expect" <<< "$out" || { echo "FAIL: missing $expect"; bad=1; }
grep -qF "$value" <<< "$out" || { echo "FAIL: missing $value"; bad=1; }
if grep -E 'command not found|syntax error|division by 0|bad substitution|arithmetic|invalid arithmetic' <<< "$out"; then echo 'FAIL: shell error'; bad=1; fi

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
