#!/bin/bash
# The tool says some settings change live on some versions, and not on others. This asks real
# servers. Each line: image, setting, value, and what must happen: live or restart.
set -u
bad=0

wait_db() {
    local client=$1 i
    for ((i = 0; i < 90; i++)); do
        docker exec lha-sql "$client" -uroot -pt -NBe 'SELECT 1' >/dev/null 2>&1 && return 0
        sleep 2
    done
    return 1
}

check() {
    local image=$1 setting=$2 value=$3 want=$4 client=mysql env=MYSQL_ROOT_PASSWORD=t got out
    if [[ $image == mariadb:* ]]; then
        env=MARIADB_ROOT_PASSWORD=t
        case ${image#mariadb:} in 10.[0-5]*) client=mysql ;; *) client=mariadb ;; esac
    fi
    docker rm -f lha-sql >/dev/null 2>&1
    docker run -d --name lha-sql -e "$env" "$image" >/dev/null
    if ! wait_db "$client"; then
        printf 'FAIL %s did not start\n' "$image"
        docker logs --tail 20 lha-sql
        bad=1
        return
    fi
    out=$(docker exec lha-sql "$client" -uroot -pt -e "SET GLOBAL $setting = $value" 2>&1 | grep -v 'Using a password')
    if [[ -z $out ]]; then got=live; else got=restart; fi
    if [[ $got == "$want" ]]; then
        printf 'ok   %-16s %-28s %s\n' "$image" "$setting" "$got"
    else
        printf 'FAIL %-16s %-28s got %s, want %s: %s\n' "$image" "$setting" "$got" "$want" "$out"
        bad=1
    fi
    docker rm -f lha-sql >/dev/null 2>&1
}

check mariadb:10.5 innodb_log_file_size 268435456 restart
check mariadb:10.8 innodb_log_file_size 268435456 restart
check mariadb:10.9 innodb_log_file_size 268435456 live
check mariadb:10.11 innodb_log_file_size 268435456 live
check mariadb:11.4 innodb_log_file_size 268435456 live
check mariadb:11.8 innodb_log_file_size 268435456 live
check mariadb:10.5 innodb_buffer_pool_size 268435456 live
check mariadb:11.8 innodb_buffer_pool_size 268435456 live
check mysql:5.7 innodb_log_file_size 268435456 restart
check mysql:5.7 innodb_buffer_pool_size 268435456 live
check mysql:8.0 innodb_redo_log_capacity 268435456 live
check mysql:8.4 innodb_redo_log_capacity 268435456 live
check mysql:8.4 innodb_buffer_pool_size 268435456 live

((bad == 0)) && echo 'version rules OK'
exit "$bad"
