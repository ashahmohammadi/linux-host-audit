#!/bin/bash
# Fake server tools. Called as: fake-tools.sh <tool> <args...>, with SCENARIO set by run.sh.
# Output mimics the real tools, so the audit's parsers can be tested without a server.
tool=$1
shift
args=" $* "
ESC=$'\033'

case $tool in
hostname) echo sim-node-01 ;;
uname) case $1 in -s) echo Linux ;; -r) echo 6.8.0-45-generic ;; -m) echo x86_64 ;; *) echo 'Linux 6.8.0-45-generic x86_64' ;; esac ;;
getconf) echo 4 ;;
systemd-detect-virt) echo kvm ;;
timedatectl) [[ $SCENARIO == broken ]] && echo no || echo yes ;;
date) if [[ $1 == +%s ]]; then echo 1793000000; elif [[ $1 == -d ]]; then echo 1793200000; else echo '2026-11-04 21:00 UTC'; fi ;;
df)
    if [[ $SCENARIO == broken ]]; then
        if [[ $args == *' -lP -i '* || $args == *' -i '* ]]; then
            printf 'Filesystem Inodes IUsed IFree IUse%% Mounted on\n/dev/sda1 1000 950 50 95%% /\n'
        else
            printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000000 97000000 3000000 97%% /\n/dev/sdb1 500000000 430000000 70000000 86%% /data\ntmpfs 1000 0 1000 0%% /run\noverlay 100 90 10 90%% /var/lib/docker/overlay2/abc/merged\n/dev/loop3 100 100 0 100%% /snap/core/1\n'
        fi
    else
        printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100000000 30000000 70000000 30%% /\n'
    fi ;;
ip)
    case $args in
        *' route get '*) echo '1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0' ;;
        *' route show default '*) [[ $SCENARIO == broken ]] || echo 'default via 10.0.0.1 dev eth0' ;;
        *' route show '*) echo 'default via 10.0.0.1 dev eth0' ;;
        *' -brief '*) echo 'eth0 UP 10.0.0.5/24' ;;
    esac ;;
ss)
    if [[ $1 == -s ]]; then echo 'Total: 120'; exit 0; fi
    echo 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
    echo 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=800,fd=3))'
    echo 'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=800,fd=4))'
    echo 'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=900,fd=6))'
    echo 'tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=900,fd=7))'
    echo 'tcp LISTEN 0 70 127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=950,fd=20))'
    echo 'tcp LISTEN 0 80 10.0.0.5:9999 0.0.0.0:* users:(("acme-custom-app",pid=1200,fd=9))'
    echo 'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=13))'
    if [[ $SCENARIO == broken ]]; then
        echo 'tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=960,fd=6))'
        echo 'tcp LISTEN 0 128 0.0.0.0:2375 0.0.0.0:* users:(("dockerd",pid=970,fd=6))'
    fi ;;
ufw) [[ $SCENARIO == clean ]] && echo 'Status: active' || echo 'Status: inactive' ;;
systemctl)
    case $args in
        *list-unit-files*) printf 'nginx.service enabled enabled\nacme-custom-app.service enabled enabled\n' ;;
        *' --state=running '*) printf 'nginx.service loaded active running A high performance web server\nacme-custom-app.service loaded active running Acme billing engine\ncron.service loaded active running Regular background program\nsystemd-journald.service loaded active running Journal\n' ;;
        *list-units*)
            printf 'nginx.service loaded active running nginx\nacme-custom-app.service loaded active running Acme\n'
            [[ $SCENARIO != broken ]] || printf 'mariadb.service loaded failed failed MariaDB\nbackupd.service loaded failed failed Backup\n' ;;
        *list-timers*) echo 'Wed 2026-11-05 00:00:00 UTC 3h left - - certbot.timer certbot.service' ;;
        *' show '*) printf 'LoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\nResult=exit-code\nExecMainCode=1\nExecMainStatus=203\nMainPID=0\nNRestarts=4\nType=simple\nConditionResult=yes\nAssertResult=yes\nTriggeredBy=\nInvocationID=\nStateChangeTimestamp=Wed 2026-11-04 20:00:00 UTC\n' ;;
    esac ;;
journalctl)
    case $args in
        *' -k '*)
            if [[ $SCENARIO == broken ]]; then
                echo 'Nov 04 kernel: Out of memory: Killed process 4242 (java)'
                echo 'Nov 04 kernel: blk_update_request: I/O error, dev sda, sector 123'
                echo 'Nov 04 kernel: EXT4-fs error (device sda1): bad block'
            fi ;;
        *' -t sshd '*) [[ $SCENARIO != broken ]] || printf 'Failed password for root\nInvalid user admin\nFailed password for root\n' ;;
        *' -p err '*) echo 'Nov 04 sim app[1]: example error' ;;
        *' --disk-usage '*) echo 'Archived and active journals take up 120.0M in the file system.' ;;
    esac ;;
docker|podman)
    [[ $SCENARIO == broken || $SCENARIO == clean ]] || exit 127
    if [[ $tool == podman ]]; then exit 1; fi
    if [[ $SCENARIO == clean ]]; then
        case $args in
            *' ps '*) echo 'web|nginx:1.27|Up 3 days (healthy)|0.0.0.0:8080->80/tcp' ;;
            *' inspect '*) echo '/web false false 0' ;;
        esac
        exit 0
    fi
    case $args in
        *' ps '*)
            echo 'web|nginx:1.27|Up 3 days (healthy)|0.0.0.0:8080->80/tcp'
            echo 'api|acme/api:2|Up 2 hours (unhealthy)|'
            echo 'worker|acme/worker:2|Restarting (1) 5 seconds ago|'
            echo 'job|acme/job:2|Exited (1) 3 hours ago|'
            echo 'mem|acme/mem:2|Exited (137) 3 hours ago|'
            echo 'old|acme/old:1|Exited (0) 9 days ago|'
            echo 'stopped|acme/x:1|Exited (143) 9 days ago|'
            echo "evil${ESC}[2Jname|postgres:16|Up 1 hour|" ;;
        *' inspect '*)
            echo '/web false false 0'
            echo '/api true true 14' ;;
        *' stats '*) echo 'web|0.10%|20MiB / 1GiB|1kB / 2kB' ;;
        *' system df '*) printf 'TYPE TOTAL ACTIVE SIZE RECLAIMABLE\nImages 5 3 2GB 1GB (50%%)\n' ;;
        *' version '*) echo 27.3.1 ;;
        *' info '*) echo 'overlay2, data in /var/lib/docker, swarm inactive' ;;
        *' network ls '*) printf 'bridge (bridge)\nhost (host)\nnone (null)\nappnet (bridge)\n' ;;
        *' compose ls '*) printf 'NAME STATUS\nacme running(3)\n' ;;
        *' logs '*) echo 'FATAL: password=hunter2-in-a-log'; ;;
    esac ;;
kubectl)
    [[ $SCENARIO == broken ]] || exit 1
    case $args in
        *'jsonpath'*) printf 'worker-2 Ready DiskPressure \nworker-1 MemoryPressure \n' ;;
        *' get nodes --no-headers '*) printf 'cp-1 Ready control-plane 90d v1.31.0\nworker-1 Ready <none> 90d v1.31.0\nworker-2 NotReady <none> 90d v1.31.0\nworker-3 Ready,SchedulingDisabled <none> 90d v1.31.0\n' ;;
        *' get pods -A --no-headers '*)
            echo 'kube-system coredns-1 1/1 Running 0 90d'
            echo 'prod api-1 0/1 CrashLoopBackOff 44 (2m ago) 3h'
            echo 'prod web-1 1/2 Running 2 (3d ago) 3d'
            echo 'prod img-1 0/1 ImagePullBackOff 0 1h'
            echo 'prod flaky-1 1/1 Running 25 (1h ago) 9d'
            echo 'jobs done-1 0/1 Completed 0 1d'
            echo 'prod pend-1 0/1 Pending 0 5m' ;;
        *' get deploy -A --no-headers '*) printf 'prod api 0/3 3 0 9d\nprod web 2/2 2 2 9d\n' ;;
        *' get pvc -A --no-headers '*) printf 'prod data-0 Pending x 1Gi RWO std 1d\nprod ok-0 Bound x 1Gi RWO std 1d\n' ;;
        *' get svc -A --no-headers '*) printf 'prod web LoadBalancer 10.0.0.1 1.2.3.4 443:30000/TCP 9d\nprod int ClusterIP 10.0.0.2 <none> 80/TCP 9d\n' ;;
        *' get secret'*) echo 'SECRET-MUST-NOT-APPEAR' ;;
        *' top nodes '*) printf 'NAME CPU MEMORY\ncp-1 10%% 40%%\n' ;;
        *' config current-context '*) echo sim-cluster ;;
        *' get events '*) echo 'prod 2m Warning BackOff pod/api-1 Back-off restarting failed container' ;;
        *) echo "NAMESPACE NAME OUTPUT $1" ;;
    esac ;;
mysql|mariadb)
    if [[ $SCENARIO == broken ]]; then echo 'ERROR 2002: Cannot connect' >&2; exit 1; fi
    if [[ $args == *'SLAVE'* ]]; then exit 0; fi
    printf 'Threads_connected\t95\nUptime\t90000\nmax_connections\t100\n' ;;
redis-cli)
    if [[ $args == *ping* ]]; then echo PONG
    else
        status=ok
        [[ $SCENARIO != broken ]] || status=err
        printf 'used_memory_human:2M\r\nconnected_clients:3\r\nrole:master\r\nrdb_last_bgsave_status:%s\r\n' "$status"
    fi ;;
iptables) echo '-P INPUT ACCEPT' ;;
apt-get) printf 'Inst libssl3 [3.0] (3.1 Ubuntu:24.04/noble-security [amd64])\nInst vim [1] (2 Ubuntu:24.04/noble-updates [amd64])\n' ;;
crontab) echo '0 3 * * * /usr/local/bin/cleanup.sh' ;;
last) echo 'reboot   system boot  6.8.0 Wed Nov  4 10:00   still running' ;;
ps)
    # Real ps can show a password in arguments; the audit must only ask for comm.
    if [[ $args == *args* || $args == *cmd* || $args == *' aux '* ]]; then echo 'mysql -pSECRET-ARG'; exit 0; fi
    if [[ $args == ' -eo comm= ' ]]; then
        printf 'nginx\nsshd\n'
        [[ $SCENARIO == bare ]] || printf 'dockerd\nkubelet\nmariadbd\nredis-server\n'
        exit 0
    fi
    printf '12.0 3.0 root nginx\n1.0 2.0 root sshd\n' ;;
esac
exit 0
