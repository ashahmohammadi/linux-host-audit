#!/bin/bash
# Simulated servers for linux-host-audit.sh. Run: bash tests/run.sh
here=$(cd "$(dirname "$0")" && pwd)
script=$here/../linux-host-audit.sh
fake=$(mktemp -d)
trap 'rm -rf "$fake"' EXIT
pass=0 fail=0
kcfg=$fake/kubeconfig
: > "$kcfg"

for tool in hostname uname getconf systemd-detect-virt timedatectl date df ip ss ufw systemctl journalctl \
    docker podman kubectl mysql mariadb redis-cli apt-get crontab last ps iptables; do
    printf '#!/bin/bash\nexec bash "%s" %s "$@"\n' "$here/fake-tools.sh" "$tool" > "$fake/$tool"
    chmod +x "$fake/$tool"
done

audit() { SCENARIO=$scenario LHA_TEST_PATH=$fake LHA_TEST_UID=${uid:-0} KUBECONFIG=${kcfg:-} NO_COLOR=1 bash "$script" "$@" 2>&1; }

has_text() {
    if grep -qF -- "$2" <<< "$1"; then ((pass += 1)); else ((fail += 1)); printf 'FAIL [%s] missing: %s\n' "$scenario" "$2"; fi
}
no_text() {
    if grep -qF -- "$2" <<< "$1"; then ((fail += 1)); printf 'FAIL [%s] must not appear: %s\n' "$scenario" "$2"; else ((pass += 1)); fi
}
equals() {
    if [[ $1 == "$2" ]]; then ((pass += 1)); else ((fail += 1)); printf 'FAIL [%s] %s: got %s want %s\n' "$scenario" "$3" "$1" "$2"; fi
}

scenario=broken
out=$(audit --report)
# Identity and generic app discovery
has_text "$out" 'sim-node-01'
has_text "$out" 'acme-custom-app'
has_text "$out" 'Acme billing engine'
# Disk filter keeps real disks and drops overlay, loop, tmpfs
has_text "$out" 'Disk / is 97% full'
has_text "$out" 'Disk /data is 86% full'
no_text "$out" 'Disk /run'
no_text "$out" 'overlay2/abc'
no_text "$out" '/snap/core'
has_text "$out" 'Disk / used 95% of its inodes'
# Services
has_text "$out" 'Service mariadb.service has failed'
has_text "$out" 'EXEC (executable or interpreter could not run)'
# Network
has_text "$out" 'Docker API is open without encryption'
has_text "$out" 'Redis/Valkey is reachable from the network'
has_text "$out" 'No active firewall was found'
has_text "$out" 'No default route'
# Containers: each status class
has_text "$out" 'Container api is unhealthy'
has_text "$out" 'Container worker keeps restarting'
has_text "$out" 'Container job stopped with error code 1'
has_text "$out" 'Container mem was killed (exit 137)'
no_text "$out" 'Container old stopped'
no_text "$out" 'Container stopped stopped'
has_text "$out" 'Container api runs in privileged mode'
has_text "$out" 'Container api was killed for memory'
has_text "$out" 'Container api restarted 14 times'
has_text "$out" 'Compose projects'
# Kubernetes parsing, including the "44 (2m ago)" restart column
has_text "$out" '3/4 nodes ready'
has_text "$out" 'Node worker-2 is not Ready'
no_text "$out" 'Node worker-3 is not Ready'
has_text "$out" 'Node worker-2 is short of disk'
has_text "$out" 'Node worker-1 is short of memory'
has_text "$out" '4 pods are not healthy'
no_text "$out" 'done-1'
has_text "$out" '2 pods restarted 10 times or more'
has_text "$out" '1 deployments lack ready replicas'
has_text "$out" '1 storage claims are not bound'
has_text "$out" 'LoadBalancer'
has_text "$out" 'Back-off restarting'
# Data, logs, security
has_text "$out" 'MySQL/MariaDB is not answering'
has_text "$out" 'Redis cannot save to disk'
has_text "$out" 'Redis answers with no password on a public port'
has_text "$out" 'Kernel logged 2 disk errors recently'
has_text "$out" 'Killed in the last 7 days: java x1'
has_text "$out" 'Last result: exit-code, exit status 203'
has_text "$out" '1 security updates are waiting (2 updates in total)'
has_text "$out" 'clock is not synchronized'
has_text "$out" 'No backup tool or backup job was found'
# Safety: no secrets, no terminal escape injection, nothing destructive asked of tools
no_text "$out" 'SECRET-MUST-NOT-APPEAR'
no_text "$out" 'SECRET-ARG'
if grep -q $'\033' <<< "$out"; then ((fail += 1)); echo 'FAIL [broken] raw escape byte reached the output'; else ((pass += 1)); fi

audit --check >/dev/null
equals "$?" 2 'exit code of --check'

scenario=clean kcfg=
out=$(audit --overview)
has_text "$out" 'UFW active'
no_text "$out" 'Only 0% of RAM'
has_text "$out" 'docker'
has_text "$out" '1 running, 0 stopped, 0 unhealthy'
no_text "$out" 'CRIT]'
out=$(audit --db)
kcfg=$fake/kubeconfig
has_text "$out" 'connections 95 of 100'

scenario=broken uid=1000
out=$(audit --overview)
has_text "$out" 'limited user: run with sudo'
has_text "$out" 'Firewall: unknown (needs root)'
uid=0

scenario=bare kcfg=
out=$(audit --report)
has_text "$out" 'No container engine or VM platform found'
has_text "$out" 'Kubernetes was not found'
has_text "$out" 'Nginx'
no_text "$out" 'Container '
kcfg=$fake/kubeconfig
no_text "$out" 'command not found'
no_text "$out" 'syntax error'
no_text "$out" 'unbound'

scenario=broken
for flag in --overview --problems --apps --network --containers --docker --k8s --web --db --security \
    --logs --jobs --resources --learn --metrics --help --version; do
    out=$(audit "$flag")
    equals "$?" 0 "exit code of $flag"
    no_text "$out" 'command not found'
    no_text "$out" 'syntax error'
done
audit --nonsense >/dev/null
equals "$?" 2 'exit code of an unknown flag'
out=$(SCENARIO=broken LHA_TEST_PATH=$fake bash "$script" --text --found-only 2>&1)
has_text "$out" 'Recognized software'

printf '%d passed, %d failed\n' "$pass" "$fail"
((fail == 0))
