#!/bin/bash
# Simulated servers for linux-host-audit.sh. Run: bash tests/run.sh
here=$(cd "$(dirname "$0")" && pwd)
script=$here/../linux-host-audit.sh
fake=$(mktemp -d)
trap 'rm -rf "$fake"' EXIT
pass=0 fail=0
kcfg=$fake/kubeconfig
: > "$kcfg"

# Every call lands in $fake/calls. The audit must never touch the tools that write something.
for tool in hostname uname getconf systemd-detect-virt timedatectl date df ip ss ufw systemctl journalctl \
    docker podman kubectl mysql mariadb redis-cli valkey-cli apt-get crontab last ps iptables ip6tables zpool \
    postqueue postconf postfix rpm sshd httpd php-fpm8.2 curl su dnf yum gluster ceph rabbitmqctl nodetool pm2; do
    printf '#!/bin/bash\necho "%s $*" >> "%s/calls"\nexec bash "%s" %s "$@"\n' "$tool" "$fake" "$here/fake-tools.sh" "$tool" > "$fake/$tool"
    chmod +x "$fake/$tool"
done
printf '#!/bin/bash\nexec "$@"\n' > "$fake/setsid"
chmod +x "$fake/setsid"

root=$fake/root
fixer=$here/../linux-host-fix.sh

audit() { SCENARIO=$scenario LHA_TEST_PATH=$fake LHA_TEST_ROOT=$root LHA_TEST_UID=${uid:-0} KUBECONFIG=${kcfg:-} NO_COLOR=1 bash "$script" "$@" 2>&1; }

# Runs code inside the script, for parsers and helpers a whole run cannot reach.
inside() {
    local file=$script
    if [[ $1 == --fixer ]]; then file=$fixer; shift; fi
    SCENARIO=$scenario LHA_TEST_PATH=$fake LHA_TEST_ROOT=$root LHA_TEST_UID=0 NO_COLOR=1 PATH="$fake:$PATH" \
        FX_TEST_HOME=$fake/fx bash -c 'source <(sed "\$d" "$1") >/dev/null; export LC_ALL=C; LHA_UID=0; ui_colors; FX_HOME=$FX_TEST_HOME FX_LOCK=$FX_TEST_HOME.lock; '"$1" _ "$file" 2>&1
}

mkdir -p "$root/var/log/nginx" "$root/var/log/redis" "$root/var/log/mysql"
{
    for ip in 1.1.1.1 2.2.2.2 3.3.3.3; do
        printf '2026/11/04 10:00:01 [error] 12#12: *%s connect() failed (111: Connection refused) while connecting to upstream, client: %s, server: a.example, request: "GET /?token=abc123secret HTTP/1.1"\n' "$RANDOM" "$ip"
    done
    printf '2026/11/04 10:00:02 [notice] 12#12: signal process started\n'
    printf '2026/11/04 10:00:03 [error] 12#12: login failed with password=hunter3secret for https://bob:s3cret@db.example/x\n'
    printf '2026/11/04 10:00:04 [crit] 12#12: evil \033[2Jname Authorization: Bearer abcdef0123456789\n'
    printf '2026/11/04 10:00:05 [emerg] 12#12: bind() to 0.0.0.0:80 failed (98: Address already in use)\n'
} > "$root/var/log/nginx/error.log"
printf '2026-11-04T10:00:00Z 8 [ERROR] [MY-010000] Too many connections\n' > "$root/var/log/mysql/error.log"
printf '1:M 04 Nov 2026 10:00:00.000 # Can'"'"'t save in background: fork: Cannot allocate memory\n1:M 04 Nov 2026 10:00:01.000 * Ready to accept connections\n' > "$root/var/log/redis/redis-server.log"

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
# Log lines stay in their own view.
no_text "$out" 'while connecting to upstream'
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

# The contract for scripts and a future fixer: valid JSON, and every finding has a stable id.
out=$(audit --json)
report=$(python -c '
import json, sys
d = json.load(sys.stdin)
ids = [f["id"] for f in d["findings"]]
print("valid", len(ids), "unknown" in ids, "service-failed" in ids, "disk-full" in ids)
targets = {f["id"]: f["target"] for f in d["findings"]}
print(targets.get("container-unhealthy"), d["host"]["package_manager"], d["listeners"][0]["port"])
' <<< "$out" 2>&1)
has_text "$report" 'False True True'
has_text "$report" 'api apt-get 22'
missing=$(grep -nE '(^|[ (])finding ("\$|[A-Z]{4} )' "$script" | grep -v 'fid=')
equals "$missing" '' 'finding without an id'

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

# Trends: ten days of made-up history with a known answer. Disk grows 1% a day, from 50 to 60.
trend=$fake/history
mkdir -p "$trend"
now=$(date +%s)
for ((d = 10; d >= 0; d--)); do
    for h in 0 6 12 18; do
        t=$((now - d * 86400 + h * 3600 - 86400))
        printf '%s,%s,0.5,40,0,%s,12,3,4,0\n' "$t" "$((h == 12 && d == 3 ? 90 : 10))" "$((60 - d))"
    done
done > "$trend/2026-01.csv"
out=$(LHA_TREND_DIR=$trend SCENARIO=clean LHA_TEST_PATH=$fake NO_COLOR=1 bash "$script" --trends month 2>&1)
has_text "$out" 'Trends: last 30 days'
has_text "$out" 'peak 90%'
has_text "$out" 'fills in about 40 days'
out=$(LHA_TREND_DIR=$fake/empty SCENARIO=clean LHA_TEST_PATH=$fake NO_COLOR=1 bash "$script" --trends 2>&1)
has_text "$out" 'Nothing has been recorded yet'

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
    --logs --errors --tune --jobs --resources --learn --metrics --help --version; do
    out=$(audit "$flag")
    equals "$?" 0 "exit code of $flag"
    no_text "$out" 'command not found'
    no_text "$out" 'syntax error'
done
audit --nonsense >/dev/null
equals "$?" 2 'exit code of an unknown flag'
out=$(SCENARIO=broken LHA_TEST_PATH=$fake bash "$script" --text --found-only 2>&1)
has_text "$out" 'Recognized software'

# The error view: bounded, grouped, explained, masked and clean.
scenario=broken
out=$(audit --errors)
has_text "$out" 'They appear only here'
has_text "$out" '/var/log/nginx/error.log'
has_text "$out" '3x'
has_text "$out" 'The app behind the web server is down'
has_text "$out" 'The port this program wants is already taken'
no_text "$out" 'signal process started'
no_text "$out" 'abc123secret'
no_text "$out" 'hunter3secret'
no_text "$out" 's3cret@'
no_text "$out" 'abcdef0123456789'
no_text "$out" 'hunter2'
has_text "$out" 'password=***'
has_text "$out" 'Container api'
has_text "$out" 'Too many connections'
has_text "$out" 'Redis could not fork to save'
no_text "$out" 'Ready to accept'
if grep -q $'\033' <<< "$out"; then ((fail += 1)); echo 'FAIL [errors] raw escape byte reached the output'; else ((pass += 1)); fi
out=$(inside 'ERR_BYTES=40 ERR_LINES=2; for i in 1 2 3 4 5 6 7 8 9; do echo "line number $i"; done > "$LHA_ROOT/big"; err_tail "$LHA_ROOT/big"; echo; c_dim= c_off= c_grn=; printf "a error\nb note\n" | err_group error')
has_text "$out" 'line number 9'
no_text "$out" 'line number 7'
has_text "$out" '@@@ 1 1'
out=$(inside 'SVC_FAILED=; sig_rows=; CT_N=0; view_errors')
has_text "$out" 'No known application'
equals "$(inside 'err_hints | awk -F "~" "NF != 3"')" '' 'every hint has a pattern, a cause and a next step'

# Tools that write, start something, or log a login. The audit must never have called them.
calls=$(cat "$fake/calls")
for word in 'zpool' 'su ' 'crontab' 'dnf' 'yum' 'rpm' 'gluster' 'ceph' 'rabbitmqctl' 'nodetool' 'pm2' 'postfix'; do
    if grep -qE "^$word" <<< "$calls"; then ((fail += 1)); printf 'FAIL audit called %s\n' "$word"; else ((pass += 1)); fi
done

# Regressions: one test for each defect found in review.
scenario=clean
lint=$(grep -nE '\[\[:[a-z]+:\]\]|\{[0-9]+,[0-9]*\}' "$script")
equals "$lint" '' 'POSIX classes or intervals break awk on mawk 1.3.3'
lint=$(cat "$script" "$here"/../fix/*.sh | grep -nE '\$\{[a-zA-Z_]+(,,?|\^\^?)\}|mapfile|readarray|(declare|local) -A')
equals "$lint" '' 'Bash 4 syntax'

out=$(inside 'R_OOM=0; kernel_log() { echo "kernel: Out of memory: Killed process 1 (java)"; }; check_logs; printf "%s\n" "${F_TITLE[@]}"')
has_text "$out" 'in the last 7 days'
no_text "$out" 'killed 0'

scenario=replica84
out=$(inside 'check_mysql running; printf "%s\n%s\n" "$DB_ROWS" "${F_TITLE[@]}"')
has_text "$out" 'MySQL replication is stopped'
has_text "$out" '7s behind'
scenario=replica104
out=$(inside 'check_mysql running; printf "%s\n" "$DB_ROWS"')
has_text "$out" '3s behind'
scenario=clean

mkdir -p "$root/etc/ssh/sshd_config.d"
printf 'PermitRootLogin no\n' > "$root/etc/ssh/sshd_config.d/10.conf"
printf 'Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPort 2222\nMatch User bob\n  PasswordAuthentication no\n' > "$root/etc/ssh/sshd_config"
out=$(inside 'sshd_file_settings "$LHA_ROOT/etc/ssh/sshd_config"')
has_text "$out" 'permitrootlogin no'
has_text "$out" 'port 2222'
no_text "$out" 'passwordauthentication'
printf 'PermitRootLogin Yes\n' > "$root/etc/ssh/sshd_config"
rm -f "$root/etc/ssh/sshd_config.d/10.conf"
has_text "$(inside 'sshd_file_settings "$LHA_ROOT/etc/ssh/sshd_config"')" 'permitrootlogin yes'

equals "$(inside 'printf "/boot/vmlinuz-lts\n/boot/vmlinuz-linux\n" | kernel_newest')" '' 'kernel file names that are no version'
equals "$(inside 'printf "/boot/vmlinuz-6.8.0-9-generic\n/boot/vmlinuz-6.8.0-45-generic\n" | kernel_newest')" '6.8.0-45-generic' 'newest kernel'
equals "$(inside 'client_version <<< "mariadb from 11.4.2-MariaDB, client 15.2 for debian-linux-gnu"')" 11.4 'MariaDB 11 version line'
equals "$(inside 'client_version <<< "mysql  Ver 14.14 Distrib 5.7.44, for Linux"')" 5.7 'MySQL 5.7 version line'
equals "$(inside 'client_version <<< "mysql  Ver 8.0.36 for Linux on x86_64"')" 8.0 'MySQL 8 version line'

out=$(inside 'sig_rows="x|MariaDB server|RUNNING|"$'"'"'\n'"'"'; R_MEM_TOTAL=8589934592; TUNE_ROWS=; tune_mysql; printf "%s" "$TUNE_ROWS"')
pool=$(awk -F '|' '$2 == "innodb_buffer_pool_size" { print $9 }' <<< "$out")
equals "$pool" 728936480768 'a very large pool must not overflow'
equals "$(awk -F '|' '$2 == "innodb_log_file_size" { print $9 }' <<< "$out")" 536870912 'redo log advice is per file'
has_text "$out" 'innodb_log_file_size|50.0 MiB|'
has_text "$out" 'query_cache_type|ON|'
out=$(LHA_TUNE_MATURE=300000 inside 'sig_rows="x|MariaDB server|RUNNING|"; R_MEM_TOTAL=8589934592; TUNE_ROWS=; tune_mysql; printf "%s" "$TUNE_ROWS"')
no_text "$out" 'query_cache_type|ON|'
equals "$(awk -F '|' 'NF && $6 != ""' <<< "$out")" '' 'a young MySQL gets no advice at all'

scenario=redisport
inside 'net_collect; check_redis Redis redis-cli' >/dev/null
has_text "$(cat "$fake/calls")" 'redis-cli -h 127.0.0.1 -p 6380 ping'
scenario=redissock
out=$(inside 'NET_ROWS="tcp 22 public 0.0.0.0 sshd 1"; check_redis Redis redis-cli; printf "%s\n%s\n" "$DB_ROWS" "${F_TITLE[@]}"')
has_text "$out" 'no TCP port'
no_text "$out" 'is not answering'
scenario=clean
tuned='sig_rows=; R_MEM_TOTAL=2097152; TUNE_ROWS=; tune_redis Redis redis-cli; printf "%s" "$TUNE_ROWS$TUNE_NOTES"'
out=$(FAKE_REDIS_USED=900000000 FAKE_UPTIME=100 inside "$tuned")
has_text "$out" 'Running for only'
equals "$(awk -F '|' '$2 == "maxmemory" { print $6 }' <<< "$out")" '' 'a young Redis gets no advice'
out=$(FAKE_REDIS_USED=900000000 FAKE_UPTIME=200000 inside "$tuned")
equals "$(awk -F '|' '$2 == "maxmemory" { print $9 }' <<< "$out")" '' 'advice that does not fit in RAM is dropped'
out=$(FAKE_REDIS_USED=300000000 FAKE_UPTIME=200000 inside "$tuned")
has_text "$out" 'it already uses a real part of RAM'
out=$(FAKE_REDIS_USED=2097152 FAKE_UPTIME=200000 inside "$tuned")
equals "$(awk -F '|' '$2 == "maxmemory" { print $6 }' <<< "$out")" '' 'a small Redis is no evidence'

out=$(inside 'sig_rows= sig_groups= diagnostic_units=; packages=; units=$'"'"'\n'"'"'; active_units=$'"'"'\n'"'"'; processes=$'"'"'\nphp-fpm7.4\n'"'"'; index_evidence; signatures; sig_list RUNNING "^PHP-FPM"')
has_text "$out" 'PHP-FPM'
scenario=fpm
out=$(inside 'sig_rows="x|PHP-FPM|RUNNING|"$'"'"'\n'"'"'; TUNE_ROWS=; TUNE_NOTES=; tune_phpfpm; printf "%s" "$TUNE_ROWS$TUNE_NOTES"')
has_text "$out" 'www'
scenario=clean

mkdir -p "$root/proc/net" "$root/proc/sys/net/ipv4"
{
    printf '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
    printf '   0: 0100007F:0050 0100007F:9C40 01 00000000:00000000 00:00000000 00000000 0 0 11 1\n'
    printf '   1: 0100007F:0050 0100007F:9C41 06 00000000:00000000 00:00000000 00000000 0 0 0 1\n'
    printf '   2: 0500000A:9C40 0100007F:0050 06 00000000:00000000 00:00000000 00000000 0 0 0 1\n'
    printf '   3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 22 1\n'
} > "$root/proc/net/tcp"
{
    printf '  sl  local_address                         remote_address   st tx rx tr tm retr uid timeout inode\n'
    printf '   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 33 1\n'
    printf '   1: 0000000000000000FFFF00000100007F:1F91 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 34 1\n'
} > "$root/proc/net/tcp6"
printf '  sl  local_address rem_address st tx rx tr tm retr uid timeout inode\n   0: 00000000:0035 00000000:0000 07 0:0 0:0 0 0 0 44 1\n' > "$root/proc/net/udp"
equals "$(inside 'tune_connections 80 443')" 1 'established connections on web ports'
equals "$(inside 'tcp_count 06 32768 60999')" 1 'TIME-WAIT counts only spent outgoing ports'
out=$(inside 'proc_socket_owners() { printf "22 800\n33 801\n"; }; proc_listeners')
has_text "$out" 'tcp 22 0.0.0.0 ? 800'
has_text "$out" 'tcp 8080 :: ? 801'
has_text "$out" 'tcp 8081 ::ffff:127.0.0.1 ? -'
has_text "$out" 'udp 53 0.0.0.0 ? -'
printf '40000 40000\n' > "$root/proc/sys/net/ipv4/ip_local_port_range"
out=$(inside 'R_SWAP_USED=0 TUNE_ROWS=; sig_rows=; tune_kernel; printf "%s" "$TUNE_ROWS"')
has_text "$out" 'ip_local_port_range|40000-40000'
has_text "$out" '|10240 40000|'
no_text "$out" 'division'
rm -f "$root/proc/sys/net/ipv4/ip_local_port_range"

mkdir -p "$fake/root2/lib/modules/6.8.0-45-generic" "$fake/root2/sys/module/udp_diag"
printf 'kernel/net/ipv4/tcp_diag.ko:\nkernel/net/ipv4/udp_diag.ko:\n' > "$fake/root2/lib/modules/6.8.0-45-generic/modules.dep"
out=$(root=$fake/root2 inside 'ss_quiet tcp_diag; echo "tcp $?"; ss_quiet udp_diag; echo "udp $?"; ss_quiet other; echo "other $?"')
has_text "$out" 'tcp 1'
has_text "$out" 'udp 0'
has_text "$out" 'other 0'
: > "$fake/calls"
root=$fake/root2 inside 'net_listeners' >/dev/null
no_text "$(cat "$fake/calls")" 'ss -lntup'

cat > "$fake/server.xml" <<'XML'
<!-- A shared pool:
    <Executor name="tomcatThreadPool" maxThreads="150" minSpareThreads="4"/>
-->
<Connector port="8080" protocol="HTTP/1.1" /> <!-- maxThreads="151" -->
<Connector port="8443" maxThreads="400" />
XML
equals "$(inside "tomcat_threads '$fake/server.xml'")" 400 'maxThreads in a comment does not count'
printf '<!-- maxThreads="150" -->\n<Connector port="8080" />\n' > "$fake/server.xml"
equals "$(inside "tomcat_threads '$fake/server.xml'")" '' 'no maxThreads means the default'

mkdir -p "$root/etc/httpd/conf"
printf 'MaxRequestWorkers ${APACHE_WORKERS}\nThreadsPerChild ${APACHE_THREADS}\n' > "$root/etc/httpd/conf/httpd.conf"
out=$(inside 'sig_rows="x|Apache HTTP Server|RUNNING|"$'"'"'\n'"'"'; TUNE_ROWS=; TUNE_BUDGET=; TUNE_NOTES=; tune_apache; printf "%s" "$TUNE_ROWS$TUNE_NOTES"')
has_text "$out" 'default of 400'
no_text "$out" 'syntax error'
rm -f "$root/etc/httpd/conf/httpd.conf"

out=$(inside 'sig_rows="x|Postfix|RUNNING|"$'"'"'\n'"'"'; check_mail; printf "%s|%s\n" "$MAIL_QUEUE" "${F_NEXT[0]}"')
has_text "$out" '1200|postqueue -p'

out=$(inside 'net_listeners() { printf "tcp 8080 ::ffff:127.0.0.1 java 1\ntcp 41641 100.100.1.2 tailscaled 2\ntcp 9 ::ffff:8.8.8.8 x 3\n"; }; net_collect; printf "%s" "$NET_ROWS"')
has_text "$out" 'tcp 8080 local'
has_text "$out" 'tcp 41641 private'
has_text "$out" 'tcp 9 public'

equals "$(inside "printf 'a\\xc2\\x9b[2Jb\\xc3\\xa9\\xc2\\xa0c' | clean | od -An -c | tr -d ' \\n'")" "$(printf 'a[2Jb\303\251\302\240c' | od -An -c | tr -d ' \n')" 'C1 controls go, other text stays'
has_text "$(inside "js \$'a\\nb\\rc'")" '"a b c"'
out=$(inside 'TUNE_ROWS="K|node x|m|in use|<unknown>|||"$'"'"'\n'"'"'; TUNE_NOTES=; tune_print_group K')
no_text "$out" 'syntax error'

printf 'java\0-Xmx2g\0-Dpassword=hunter4\0kafka.Kafka\0/etc/kafka/server.properties\0' > "$fake/cmdline"
out=$(inside "runtime_role '$fake/cmdline'; echo \"role \$REPLY\"; proc_flag '$fake/cmdline' -Xmx; echo; size_bytes 2g; echo; size_bytes 512m; echo; size_bytes 12; echo; size_bytes junk")
has_text "$out" 'role kafka'
has_text "$out" '2147483648'
has_text "$out" '536870912'
no_text "$out" 'hunter4'
equals "$(inside 'runtime_role /nonexistent; echo "[$REPLY]"')" '[]' 'a process that vanished has no role'
printf 'java\0-m\0org.elasticsearch.server/org.elasticsearch.bootstrap.Elasticsearch\0' > "$fake/cmdline"
has_text "$(inside "runtime_role '$fake/cmdline'; echo \"role \$REPLY\"")" 'role elasticsearch'

# Applications added to tuning. Numbers come from the fake service, or there is only a note.
scenario=apps
everything='R_MEM_TOTAL=8388608; H_CPUS=2; TUNE_ROWS= TUNE_NOTES= TUNE_BUDGET=; NET_ROWS="tcp 3128 public 0.0.0.0 squid 1
tcp 8080 public 0.0.0.0 traefik 2"; for s in RabbitMQ ClickHouse InfluxDB MinIO "Ceph storage" GlusterFS Keepalived "Squid proxy" Caddy Traefik Gunicorn uWSGI "Apache Kafka" "Apache Cassandra"; do sig_rows+="x|$s|RUNNING|"$'"'"'\n'"'"'; done; tune_rabbitmq; tune_clickhouse; tune_influx; tune_minio; tune_ceph; tune_gluster; tune_keepalived; tune_squid; tune_caddy; tune_traefik; tune_workers Gunicorn gunicorn workers; tune_workers uWSGI uwsgi processes; tune_kafka; tune_cassandra; tune_jvm; tune_node; printf "%s\n--\n%s\n--\n%s" "$TUNE_ROWS" "$TUNE_NOTES" "$TUNE_BUDGET"'
mkdir -p "$root/etc/keepalived" "$root/etc/default" "$root/var/lib/glusterd/vols/data/bricks" "$root/var/lib/glusterd/peers" "$root/srv/brick"
printf 'vrrp_instance VI_1 {\n  virtual_ipaddress {\n    10.0.0.50/24\n    10.0.0.51\n  }\n}\n' > "$root/etc/keepalived/keepalived.conf"
printf 'MINIO_ROOT_PASSWORD=SECRET-MUST-NOT-APPEAR\nMINIO_VOLUMES="/srv/brick"\n' > "$root/etc/default/minio"
printf 'count=2\nstatus=1\n' > "$root/var/lib/glusterd/vols/data/info"
printf 'hostname=a\npath=/srv/brick\n' > "$root/var/lib/glusterd/vols/data/bricks/a"
printf 'state=3\n' > "$root/var/lib/glusterd/peers/one"
out=$(inside "$everything")
has_text "$out" 'RabbitMQ 3.13.7|vm_memory_high_watermark|1.0 GiB|256.0 MiB used|25|'
has_text "$out" '|open files|1024|900 open|87|2048|'
has_text "$out" '12 connections, 42 messages in queues'
has_text "$out" 'ClickHouse 24.8.4.13|max_connections|100|95 now|95|150|'
has_text "$out" '7 inserts were rejected'
has_text "$out" 'max_server_memory_usage|7.2 GiB'
has_text "$out" 'InfluxDB 1.8.10|InfluxDB sets no memory limit'
has_text "$out" 'MinIO|Its metrics need a token'
has_text "$out" 'Ceph|raw capacity|1.0 TiB|512.0 GiB used|50|'
has_text "$out" 'HEALTH_WARN, with 2 OSDs up of 2 in'
has_text "$out" 'Volume data has 2 bricks'
has_text "$out" '1 other servers in this pool'
has_text "$out" 'This node holds 1 of its 2 virtual addresses'
has_text "$out" 'Its manager page would write to its own log'
no_text "$(cat "$script")" 'squid-internal-mgr'
has_text "$out" 'cache_mem|config|12% used'
has_text "$out" 'Caddy v2.8.4|open files|1024|12 open|'
has_text "$out" 'Traefik|Its metrics page is off'
has_text "$out" 'Gunicorn|workers|2|'
has_text "$out" 'uWSGI|processes|1|'
has_text "$out" 'JVM services|java (pid 300) heap|JVM default|390.6 MiB in RAM'
has_text "$out" 'Node.js|pid 310|no limit set|'
no_text "$out" 'SECRET-MUST-NOT-APPEAR'
no_text "$out" 'syntax error'
no_text "$out" 'division'
out=$(FAKE_UPTIME=100 inside 'R_MEM_TOTAL=8388608; TUNE_ROWS=; TUNE_NOTES=; TUNE_BUDGET=; tune_workers Gunicorn gunicorn workers; printf "%s%s" "$TUNE_ROWS" "$TUNE_NOTES"')
has_text "$out" 'Running for only'
out=$(inside 'R_MEM_TOTAL=8388608; TUNE_ROWS=; TUNE_NOTES=; sig_rows="x|Nginx|RUNNING|"; TUNE_BUDGET=; tune_any_program; printf "%s" "$TUNE_ROWS$TUNE_NOTES"')
no_text "$out" 'syntax error'
scenario=clean
out=$(inside 'sig_rows="x|RabbitMQ|RUNNING|
x|ClickHouse|RUNNING|
"; TUNE_ROWS=; TUNE_NOTES=; TUNE_BUDGET=; tune_rabbitmq; tune_clickhouse; printf "%s%s" "$TUNE_ROWS" "$TUNE_NOTES"')
has_text "$out" 'rabbitmqctl is left out on purpose'
has_text "$out" 'Port 8123 did not answer'
no_text "$out" 'RabbitMQ|vm_memory'

# Fixer. Each of these is a defect that would have hurt a real server.
bash "$here/../make-fix.sh" >/dev/null
scenario=clean
out=$(inside --fixer 'fx_begin t; fx_write() { cat >/dev/null; fx_undo RESTORE; }; ap_ssh_root_password; cat "$FX_DIR/undo.list"')
equals "$(grep -c reload <<< "$(sed -n 1p <<< "$out")")" 1 'the reload runs after the file is back'
equals "$(tail -n 1 <<< "$out")" RESTORE 'the file is restored first'

out=$(inside --fixer 'fx_begin t; FX_DEADMAN_SECONDS=1; fx_deadman_start; fx_undo "touch $LHA_ROOT/fired"; sleep 3; ls "$LHA_ROOT"; wc -c < "$FX_DIR/undo.list"')
has_text "$out" 'fired'
out=$(inside --fixer 'rm -f "$LHA_ROOT/fired"; fx_begin t; FX_DEADMAN_SECONDS=1; fx_deadman_start; fx_undo "touch $LHA_ROOT/fired"; fx_deadman_stop; sleep 3; ls "$LHA_ROOT"')
no_text "$out" 'fired'

out=$(inside --fixer 'R_LOAD1=100; H_CPUS=1; FX_RISK=medium; fx_gates; echo "rc $?"; ls -d "$FX_LOCK" 2>&1; FX_RISK=low; fx_gates; echo "low $?"; fx_gates_end')
has_text "$out" 'wait for a quieter moment'
has_text "$out" 'rc 1'
has_text "$out" 'No such file'
has_text "$out" 'low 0'
out=$(inside --fixer 'R_LOAD1=0; H_CPUS=1; FX_RISK=low; LHA_EXIT_CMD="echo restored"; fx_gates; fx_gates_end; trap -p EXIT')
has_text "$out" 'echo restored'

out=$(inside --fixer 'NET_ROWS="tcp 22 public 0.0.0.0 sshd 1
tcp 3306 private 10.0.0.5 mariadbd 2
tcp 6379 local 127.0.0.1 redis-server 3"; fx_open_ports')
has_text "$out" '3306/tcp'
no_text "$out" '6379'
: > "$fake/calls"
out=$(inside --fixer 'fx_begin t; FX_PORT=6399; fx_block_apply; cat "$FX_DIR/undo.list"')
has_text "$(cat "$fake/calls")" 'iptables -I INPUT -p tcp --dport 6399 ! -i lo -j DROP'
has_text "$out" '-D INPUT -p tcp --dport 6399 \! -i lo -j DROP'

cat > "$fake/pool.conf" <<'POOL'
[one]
pm = dynamic
pm.max_children = 5
[two]
pm.max_children = 8
;pm.max_children = 99
POOL
out=$(inside --fixer "tune_fpm_edit '$fake/pool.conf' two 12")
has_text "$out" 'pm.max_children = 5'
has_text "$out" 'pm.max_children = 12'
has_text "$out" ';pm.max_children = 99'
no_text "$out" 'pm.max_children = 8'
equals "$(inside --fixer 'fx_phpfpm_bin php8.2-fpm.service')" php-fpm8.2 'the binary of a PHP version'

mkdir -p "$fake/cnf"
out=$(inside --fixer 'fx_begin t; TA_KIND=mysql TA_SETTING=tmp_table_size TA_RAW=33554432 TA_DIR='"$fake/cnf"' FX_SQL=mysql; ap_tune_apply; cat '"$fake/cnf/zz-linux-host-audit.cnf"' "$FX_DIR/undo.list"')
has_text "$out" 'tmp_table_size = 33554432'
has_text "$out" 'max_heap_table_size = 33554432'
has_text "$out" 'SET\ GLOBAL\ max_heap_table_size\ =\ 16777216'

out=$(inside --fixer 'fx_begin t; FX_PACKAGES=vim; timeout() { echo "limit $1"; shift; "$@"; }; ap_updates_security; fx_run true; cat "$FX_DIR/journal.log"')
has_text "$out" 'limit 3600'
has_text "$out" 'limit 300'
equals "$(inside --fixer 'FX_PACKAGES="curl libssl3"; ck_updates_security; echo $?')" 1 'one package left means not done'
equals "$(inside --fixer 'FX_PACKAGES="curl"; ck_updates_security; echo $?')" 0 'no package left means done'

: > "$fake/calls"
inside --fixer 'fx_owner_package /usr/bin/x; fx_config_test postfix.service' >/dev/null
no_text "$(cat "$fake/calls")" 'rpm '
no_text "$(cat "$fake/calls")" 'postfix check'
has_text "$(cat "$fake/calls")" 'postconf -n'

: > "$fake/swap"
equals "$(inside --fixer "H_CONTAINER=; R_SWAP_TOTAL=0; FX_SWAPFILE='$fake/swap'; fx_swap_possible; echo \$?")" 1 'an existing swap file is not ours to replace'
printf 'keep\n' > "$fake/conf"
equals "$(inside --fixer "fx_begin t; : | fx_write '$fake/conf'; cat '$fake/conf'")" keep 'an empty write must not replace a file'
has_text "$(inside --fixer 'fx_begin "disk-full /"; fx_undo_run "$FX_RUN"')" 'Nothing to undo'
has_text "$(inside --fixer 'TUNE_ROWS=; tune_done=yes; dx_tune_apply "1;w /tmp/x"; echo "$FX_CAUSE"')" 'no advice number 0'
has_text "$(inside --fixer 'F_N=1; F_ID[0]=os-eol; F_TARGET[0]="Debian GNU/Linux 11"; fx_transaction() { echo "got $2"; }; fix_from_menu os-eol:Debian GNU/Linux 11')" 'got Debian GNU/Linux 11'
has_text "$(inside --fixer 'sig_rows="x|Postfix|RUNNING|"; dx_mail_queue; printf "%s\n" "${FX_STEPS[@]}"')" 'postqueue -p'
has_text "$(inside --fixer 'fx_delegate() { echo "unit $1"; }; units=$'"'"'\nredis-server.service enabled\nvalkey.service enabled\n'"'"'; active_units=; dx_redis_down Valkey')" 'unit valkey.service'

printf '%d passed, %d failed\n' "$pass" "$fail"
((fail == 0))
