#!/bin/bash
# A real Plesk, from the vendor's own image: the audit reads it, and every read-only Plesk command
# this tool names must really exist.
set -u
image=${1:-plesk/plesk:18.0}
here=$(cd "$(dirname "$0")/.." && pwd)
bad=0

docker run -d --name lha-plesk --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /tmp --tmpfs /run --tmpfs /run/lock "$image" >/dev/null
for ((i = 0; i < 120; i++)); do
    docker exec lha-plesk plesk version >/dev/null 2>&1 && docker exec lha-plesk plesk db -NBe 'SELECT 1' >/dev/null 2>&1 && break
    sleep 5
done
docker exec lha-plesk plesk version || { echo 'FAIL Plesk did not start'; docker logs --tail 40 lha-plesk; exit 1; }

docker cp "$here/linux-host-audit.sh" lha-plesk:/root/linux-host-audit.sh
out=$(docker exec -e NO_COLOR=1 lha-plesk bash /root/linux-host-audit.sh --panel 2>&1)
printf '%s\n' "$out"

need() {
    if grep -qF -- "$1" <<< "$out"; then printf 'ok   %s\n' "$1"; else printf 'FAIL missing: %s\n' "$1"; bad=1; fi
}
need 'Plesk troubleshooting'
need 'Obsidian has no end date'
need 'sw-cp-server'
need 'plesk repair all -n'

# Reading the database through Plesk, the same way the audit does.
if docker exec lha-plesk plesk db --connect-timeout=3 -NBe 'SHOW GLOBAL VARIABLES' | grep -q '^max_connections'; then
    echo 'ok   plesk db takes the options this tool passes'
else
    echo 'FAIL plesk db did not return server variables'
    bad=1
fi
out=$(docker exec -e NO_COLOR=1 lha-plesk bash /root/linux-host-audit.sh --tune 2>&1)
need 'max_connections'

# Each must run, or print its own help, and never say the command is unknown.
for command in 'plesk version' 'plesk help repair' 'plesk help log' 'plesk bin php_handler --list' 'plesk help listupgrade' \
    'plesk help checkupgrade' 'plesk help installer'; do
    # shellcheck disable=SC2086 # the words are split on purpose
    text=$(docker exec lha-plesk $command 2>&1)
    rc=$?
    if ((rc != 0)) || grep -qiE 'unknown (command|utility)|not found' <<< "$text"; then
        printf 'FAIL %s: exit %s: %s\n' "$command" "$rc" "$(head -n 2 <<< "$text")"
        bad=1
    else
        printf 'ok   %s\n' "$command"
    fi
done

docker rm -f lha-plesk >/dev/null 2>&1
((bad == 0)) && echo 'Plesk OK'
exit "$bad"
