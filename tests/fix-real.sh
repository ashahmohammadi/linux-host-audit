#!/bin/bash
# Real break-and-fix tests. Run as root on a THROWAWAY machine only: this breaks things on purpose.
if [[ ${GITHUB_ACTIONS:-} != true && ${LHA_I_AM_DISPOSABLE:-} != yes ]]; then
    echo 'Refusing to run: this test breaks the machine on purpose. Use CI or set LHA_I_AM_DISPOSABLE=yes.'
    exit 3
fi
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1090
source <(sed '$d' "$here/../linux-host-fix.sh")
fix_main --help >/dev/null
FX_ASSUME=high LHA_FIX_SETTLE=2
FX_SETTLE=2 FX_GUARD_RETRY=6 FX_HOME=/var/lib/lha-test
pass=0 fail=0

ok() { ((pass += 1)); printf 'ok    %s\n' "$1"; }
bad() { ((fail += 1)); printf 'FAIL  %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

fresh() { checks_done=no F_N=0 F_CRIT=0 F_WARN=0 F_INFO=0; run_checks >/dev/null 2>&1; }
fresh

echo '=== engine: a fix that breaks something else is rolled back'
systemctl start nginx
dx_test_breaks() { FX_MODE=auto FX_RISK=low FX_CAUSE=test FX_PLAN=(test); }
ap_test_breaks() {
    printf 'changed\n' | fx_write /etc/lha-marker || return 1
    fx_undo 'systemctl start nginx'
    fx_run systemctl stop nginx
}
ck_test_breaks() { return 0; }
printf 'original\n' > /etc/lha-marker
out=$(fx_transaction test-breaks '' 2>&1); status=$?
echo "$out" | tail -n 3
check 'guard reports a failure' "((status == 1))"
check 'guard names the victim' "grep -q 'something else stopped' <<< \"\$out\""
check 'guard restored the file' "grep -q original /etc/lha-marker"
check 'guard restarted the service' "[[ \$(systemctl is-active nginx) == active ]]"

echo '=== engine: a fix that does not solve it is rolled back'
dx_test_useless() { FX_MODE=auto FX_RISK=low FX_CAUSE=test FX_PLAN=(test); }
ap_test_useless() { printf 'changed\n' | fx_write /etc/lha-marker; }
ck_test_useless() { return 1; }
fx_transaction test-useless '' >/dev/null 2>&1
check 'useless fix returns 1' "((\$? == 1))"
check 'useless fix restored the file' "grep -q original /etc/lha-marker"

echo '=== engine: a fix that fails midway is rolled back'
dx_test_midway() { FX_MODE=auto FX_RISK=low FX_CAUSE=test FX_PLAN=(test); }
ap_test_midway() { printf 'changed\n' | fx_write /etc/lha-marker || return 1; fx_run false; }
ck_test_midway() { return 0; }
fx_transaction test-midway '' >/dev/null 2>&1
check 'midway failure restored the file' "grep -q original /etc/lha-marker"

echo '=== engine: new files are removed on rollback, dry run changes nothing'
dx_test_new() { FX_MODE=auto FX_RISK=low FX_CAUSE=test FX_PLAN=(test); }
ap_test_new() { printf 'x\n' | fx_write /etc/lha-new-file; }
ck_test_new() { return 1; }
fx_transaction test-new '' >/dev/null 2>&1
check 'new file removed' "[[ ! -e /etc/lha-new-file ]]"
rm -rf "$FX_HOME"
FX_DRY=yes fx_transaction test-new '' >/dev/null 2>&1
check 'dry run created no transaction' "[[ ! -e \$FX_HOME/runs ]]"
check 'dry run wrote nothing' "[[ ! -e /etc/lha-new-file ]]"
FX_DRY=no

echo '=== engine: refuses without confirmation, and while locked'
FX_ASSUME=none
fx_transaction test-new '' </dev/null >/dev/null 2>&1
check 'no confirmation, no change' "[[ ! -e /etc/lha-new-file ]]"
FX_ASSUME=high
mkdir /dev/shm/linux-host-audit.lock
fx_transaction test-new '' >/dev/null 2>&1
check 'locked, no change' "[[ ! -e /etc/lha-new-file ]]"
rmdir /dev/shm/linux-host-audit.lock

echo '=== failed service: clean retry works'
cat > /etc/systemd/system/lha-flaky.service <<'EOF'
[Service]
ExecStart=/bin/sh -c 'test -f /run/lha-ok && exec sleep 600'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable lha-flaky 2>/dev/null
systemctl start lha-flaky 2>/dev/null
touch /run/lha-ok
fresh
check 'failure is detected' "fix_find service-failed:lha-flaky.service"
fx_transaction service-failed lha-flaky.service | tail -n 2
check 'service is running' "[[ \$(systemctl is-active lha-flaky) == active ]]"
systemctl stop lha-flaky

echo '=== failed service: a one-shot job is never run again'
cat > /etc/systemd/system/lha-job.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo ran >> /run/lha-job-runs; exit 1'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable lha-job 2>/dev/null
systemctl start lha-job 2>/dev/null
fresh
out=$(fx_transaction service-failed lha-job.service 2>&1); status=$?
check 'one-shot is not automatic' "((status == 3))"
check 'one-shot ran only once' "(($(wc -l < /run/lha-job-runs) == 1))"
systemctl disable lha-job 2>/dev/null; systemctl reset-failed lha-job

echo '=== failed service: a boot job in disguise is never run again'
# Same shape as rc-local on the RHEL family: not one-shot, but it stays "active" after exiting.
cat > /etc/systemd/system/lha-boot.service <<'EOF'
[Service]
Type=forking
RemainAfterExit=yes
ExecStart=/bin/sh -c 'echo ran >> /run/lha-boot-runs; exit 1'
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable lha-boot 2>/dev/null
systemctl start lha-boot 2>/dev/null
fresh
out=$(fx_transaction service-failed lha-boot.service 2>&1); status=$?
check 'boot job is not automatic' "((status == 3))"
check 'boot job ran only once' "(($(wc -l < /run/lha-boot-runs) == 1))"
systemctl disable lha-boot 2>/dev/null; systemctl reset-failed lha-boot

echo '=== failed service: one that is switched off stays off'
cat > /etc/systemd/system/lha-off.service <<'EOF'
[Service]
ExecStart=/bin/sh -c 'test -f /run/lha-off-ok && exec sleep 600'
EOF
systemctl daemon-reload
systemctl start lha-off 2>/dev/null
touch /run/lha-off-ok
fresh
out=$(fx_transaction service-failed lha-off.service 2>&1); status=$?
check 'disabled service is not started' "((status == 3))"
check 'disabled service still down' "[[ \$(systemctl is-active lha-off) != active ]]"
systemctl reset-failed lha-off

echo '=== failed service: broken config is reported and left alone'
cp /etc/nginx/nginx.conf /etc/lha-nginx.good
systemctl stop nginx
echo 'this is not valid' >> /etc/nginx/nginx.conf
systemctl start nginx 2>/dev/null
sum=$(sha256sum /etc/nginx/nginx.conf)
fresh
out=$(fx_transaction service-failed nginx.service 2>&1); status=$?
echo "$out" | head -n 4
check 'finds the broken config' "grep -q 'configuration is broken' <<< \"\$out\""
check 'gives steps, not a change' "((status == 3))"
check 'config file untouched' "[[ \$(sha256sum /etc/nginx/nginx.conf) == \"\$sum\" ]]"
cp /etc/lha-nginx.good /etc/nginx/nginx.conf
systemctl reset-failed nginx
systemctl start nginx

echo '=== failed service: port taken is named, nothing is killed'
systemctl stop nginx
python3 -m http.server 80 >/dev/null 2>&1 &
squatter=$!
sleep 2
systemctl start nginx 2>/dev/null
fresh
out=$(fx_transaction service-failed nginx.service 2>&1)
echo "$out" | head -n 3
check 'names the port problem' "grep -q 'already taken' <<< \"\$out\""
check 'other program still runs' "kill -0 $squatter"
kill "$squatter"
sleep 1
systemctl reset-failed nginx
systemctl start nginx

echo '=== kernel limit: fix, then undo'
sysctl -w fs.file-max=1000000 >/dev/null
before=1000000
fx_transaction file-limit '' | tail -n 1
run=$(ls -t "$FX_HOME/runs" | head -n 1)
check 'limit raised' "(($(sysctl -n fs.file-max) == before * 2))"
check 'kept across reboots' "grep -q fs.file-max /etc/sysctl.d/90-linux-host-audit.conf"
fx_undo_run "$run"
check 'undo restored the limit' "[[ \$(sysctl -n fs.file-max) == \"\$before\" ]]"
check 'undo removed the file' "[[ ! -e /etc/sysctl.d/90-linux-host-audit.conf ]]"

echo '=== disk: only old compressed logs go, nothing a person made'
mkdir -p /srv/site/uploads
dd if=/dev/zero bs=1M count=150 2>/dev/null | gzip -1 > /dev/null
head -c 157286400 /dev/urandom > /var/log/lha-old.log.gz
touch -d '30 days ago' /var/log/lha-old.log.gz
printf keep > /srv/site/uploads/photo.gz; touch -d '30 days ago' /srv/site/uploads/photo.gz
printf keep > /var/log/lha-new.log.gz
printf keep > /var/log/lha-current.log; touch -d '30 days ago' /var/log/lha-current.log
fx_transaction disk-full / | tail -n 8
check 'old compressed log removed' "[[ ! -e /var/log/lha-old.log.gz ]]"
check 'upload kept' "[[ -e /srv/site/uploads/photo.gz ]]"
check 'recent compressed log kept' "[[ -e /var/log/lha-new.log.gz ]]"
check 'uncompressed log kept' "[[ -e /var/log/lha-current.log ]]"

echo '=== empty password: locked, then undone'
useradd lhatest
passwd -d lhatest >/dev/null
fx_transaction empty-passwords '' | tail -n 1
check 'account locked' "passwd -S lhatest | grep -q ' L\| LK'"
fx_undo_run "$(ls -t "$FX_HOME/runs" | head -n 1)"
check 'undo restored it' "[[ \$(awk -F: '\$1 == \"lhatest\" { print \$2 }' /etc/shadow) == '' ]]"
userdel lhatest

echo '=== port block: exposed port closed from outside, undo opens it'
python3 -m http.server 6399 >/dev/null 2>&1 &
pid=$!
sleep 1
fresh
FX_MODE=auto FX_PORT=6399
fx_begin 'block test'
fx_block_apply
check 'rule added' "fx_block_check"
check 'local access still works' "curl -s -o /dev/null -m 3 http://127.0.0.1:6399/"
fx_rollback
check 'rule removed' "! fx_block_check"
kill "$pid"

echo '=== lockout protection: SSH'
if [[ ! -f /etc/ssh/sshd_config ]] || ! has sshd; then apt-get -y -qq install openssh-server >/dev/null; fi
mkdir -p /root/.ssh
: > /root/.ssh/authorized_keys
fresh
dx_ssh_root_password
check 'no key: refuses' "[[ \$FX_MODE == never ]]"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample test\n' > /root/.ssh/authorized_keys
systemctl enable --now ssh 2>/dev/null
mkdir -p /etc/ssh/sshd_config.d
printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/01-test.conf
FX_DEADMAN_SECONDS=8 FX_DEADMAN_AUTO=wait
fx_transaction ssh-root-password '' | tail -n 3
check 'change applied' "sshd -T | grep -qE '^permitrootlogin (prohibit-password|without-password)'"
sleep 12
check 'timer reverted it' "[[ \$(sshd -T | awk '\$1 == \"permitrootlogin\" { print \$2 }') == yes ]]"
check 'sshd still healthy' "sshd -t"
rm -f /etc/ssh/sshd_config.d/01-test.conf /root/.ssh/authorized_keys
rm -rf /dev/shm/linux-host-audit.lock

echo '=== lockout protection: firewall'
if has ufw; then
    ufw --force disable >/dev/null
    fresh
    FX_DEADMAN_SECONDS=8 FX_DEADMAN_AUTO=wait
    fx_transaction no-firewall '' | tail -n 3
    check 'firewall on' "ufw status | grep -q 'Status: active'"
    check 'ssh port allowed' "ufw status | grep -q '22/tcp'"
    sleep 12
    check 'timer turned it off' "ufw status | grep -q 'Status: inactive'"
    rm -rf /dev/shm/linux-host-audit.lock
fi
FX_DEADMAN_AUTO=

echo '=== containers: only the broken one restarts'
if has docker; then
    docker run -d --name lha-web nginx:1.27-alpine >/dev/null
    docker run -d --name lha-sick --health-cmd='test -f /tmp/ok' --health-interval=1s --health-retries=1 \
        alpine:3.20 sh -c 'sleep 20; touch /tmp/ok; sleep 600' >/dev/null
    sleep 6
    started=$(docker inspect -f '{{.State.StartedAt}}' lha-web)
    fresh
    fx_transaction container-unhealthy lha-sick | tail -n 2
    check 'sick container healthy' "[[ \$(docker inspect -f '{{.State.Health.Status}}' lha-sick) == healthy ]]"
    check 'other container untouched' "[[ \$(docker inspect -f '{{.State.StartedAt}}' lha-web) == \"\$started\" ]]"
    docker rm -f lha-web lha-sick >/dev/null
fi

echo '=== tuning: applied live, kept after a restart, undone cleanly'
advice() { tune_done=yes TUNE_NOTES='' TUNE_BUDGET=''; TUNE_ROWS="$1"$'\n'; }
if has mariadb || has mysql; then
    systemctl start mariadb
    sql=mariadb; has mariadb || sql=mysql
    before=$($sql -NBe 'select @@max_connections')
    want=$((before + 40))
    fresh
    advice "MariaDB 10|max_connections|$before|x|0|$want|test|live|$want"
    fx_transaction tune-apply 1 | tail -n 3
    run=$(ls -t "$FX_HOME/runs" | head -n 1)
    check 'applied live' "[[ \$($sql -NBe 'select @@max_connections') == $want ]]"
    systemctl restart mariadb
    check 'survives a restart' "[[ \$($sql -NBe 'select @@max_connections') == $want ]]"
    fx_undo_run "$run"
    check 'undo restored the value' "[[ \$($sql -NBe 'select @@max_connections') == $before ]]"
    check 'undo removed the file' "! ls /etc/mysql/*/zz-linux-host-audit.cnf 2>/dev/null | grep -q ."
    systemctl restart mariadb
    check 'still right after a restart' "[[ \$($sql -NBe 'select @@max_connections') == $before ]]"
fi
if has redis-cli; then
    systemctl start redis-server
    advice "Redis 7|maxmemory|unlimited|x|0|256 MiB|test|live|268435456"
    fx_transaction tune-apply 1 | tail -n 2
    check 'redis limit applied' "[[ \$(redis-cli config get maxmemory | tail -n 1) == 268435456 ]]"
    fx_undo_run "$(ls -t "$FX_HOME/runs" | head -n 1)"
    check 'redis limit undone' "[[ \$(redis-cli config get maxmemory | tail -n 1) == 0 ]]"
fi
if has nginx; then
    systemctl start nginx
    sum=$(sha256sum /etc/nginx/nginx.conf)
    advice "Nginx 1|worker_connections|768|x|0|4096|test|reload|4096"
    fx_transaction tune-apply 1 | tail -n 2
    check 'nginx limit applied' "grep -q 'worker_connections 4096;' /etc/nginx/nginx.conf"
    check 'nginx still running' "[[ \$(systemctl is-active nginx) == active ]]"
    fx_undo_run "$(ls -t "$FX_HOME/runs" | head -n 1)"
    check 'nginx file restored exactly' "[[ \$(sha256sum /etc/nginx/nginx.conf) == \"\$sum\" ]]"
fi
sysctl -w vm.swappiness=60 >/dev/null
advice "Linux kernel|vm.swappiness|60|x|0|10|test|live|10"
fx_transaction tune-apply 1 | tail -n 1
check 'kernel setting applied' "[[ \$(sysctl -n vm.swappiness) == 10 ]]"
fx_undo_run "$(ls -t "$FX_HOME/runs" | head -n 1)"
check 'kernel setting undone' "[[ \$(sysctl -n vm.swappiness) == 60 ]]"
FX_DRY=yes fx_transaction tune-apply 1 >/dev/null
check 'dry run does not apply' "[[ \$(sysctl -n vm.swappiness) == 60 ]]"
FX_DRY=no
advice "MariaDB 10|innodb_log_file_size|512 MiB|x|0|896.0 MiB|test|restart|939524096"
out=$(fx_transaction tune-apply 1 2>&1); status=$?
check 'restart setting is only explained' "((status == 3))"
check 'config value is a raw number' "grep -q 'innodb_log_file_size = 939524096' <<< \"\$out\""

printf '\n%d passed, %d failed\n' "$pass" "$fail"
((fail == 0))
