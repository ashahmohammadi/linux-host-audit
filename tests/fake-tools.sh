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
date) if [[ $1 == +%s ]]; then echo 1793000000; elif [[ $1 == -d ]]; then echo 1793200000; elif [[ $1 == -r ]]; then /usr/bin/date -r "$2" +%s; else echo '2026-11-04 21:00 UTC'; fi ;;
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
        *' -o addr '*) echo '2: eth0    inet 10.0.0.50/24 brd 10.0.0.255 scope global eth0' ;;
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
    fi
    [[ $SCENARIO != redisport ]] || echo 'tcp LISTEN 0 511 127.0.0.1:6380 0.0.0.0:* users:(("redis-server",pid=961,fd=6))' ;;
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
    # MySQL 8.4 has only the new statement, and MariaDB 10.4 only the old one.
    if [[ $SCENARIO == replica84 ]]; then
        if [[ $args == *'SLAVE'* ]]; then echo 'ERROR 1064: syntax' >&2; exit 1; fi
        if [[ $args == *'REPLICA'* ]]; then printf '    Replica_IO_Running: No\n   Replica_SQL_Running: Yes\n Seconds_Behind_Source: 7\n'; exit 0; fi
    elif [[ $SCENARIO == replica104 ]]; then
        if [[ $args == *'REPLICA'* ]]; then echo 'ERROR 1064: syntax' >&2; exit 1; fi
        if [[ $args == *'SLAVE'* ]]; then printf '     Slave_IO_Running: Yes\n    Slave_SQL_Running: Yes\nSeconds_Behind_Master: 3\n'; exit 0; fi
    fi
    if [[ $args == *'SLAVE'* || $args == *'REPLICA'* ]]; then exit 0; fi
    case $args in
        *'SHOW GLOBAL VARIABLES'*)
            printf 'version\t10.11.6-MariaDB\nmax_connections\t151\ninnodb_buffer_pool_size\t2199023255552\ninnodb_log_file_size\t52428800\ninnodb_log_files_in_group\t2\ntmp_table_size\t16777216\nmax_heap_table_size\t16777216\nquery_cache_type\tON\nquery_cache_size\t1048576\n'
            exit 0 ;;
        *'SHOW GLOBAL STATUS ')
            printf 'Uptime\t200000\nMax_used_connections\t9\nThreads_connected\t2\nInnodb_buffer_pool_pages_total\t134217728\nInnodb_buffer_pool_pages_free\t100000000\nInnodb_buffer_pool_reads\t1\nInnodb_buffer_pool_read_requests\t100\nInnodb_os_log_written\t59652323555\n'
            exit 0 ;;
        *'SELECT @@GLOBAL.'*) echo 16777216; exit 0 ;;
        *'SET GLOBAL'*) exit 0 ;;
        *'@@log_error'*) echo stderr; exit 0 ;;
    esac
    printf 'Threads_connected\t95\nUptime\t90000\nmax_connections\t100\n' ;;
redis-cli|valkey-cli)
    if [[ $SCENARIO == redissock ]]; then echo 'Could not connect to Redis at 127.0.0.1:6379: Connection refused'; exit 1; fi
    if [[ $args == *ping* ]]; then echo PONG
    elif [[ $args == *'config get maxclients'* ]]; then printf 'maxclients\n10000\n'
    else
        status=ok
        [[ $SCENARIO != broken ]] || status=err
        printf 'used_memory_human:2M\r\nconnected_clients:3\r\nrole:master\r\nrdb_last_bgsave_status:%s\r\n' "$status"
        printf 'redis_version:7.2.4\r\nused_memory:%s\r\nmaxmemory:0\r\nuptime_in_seconds:%s\r\n' "${FAKE_REDIS_USED:-2097152}" "${FAKE_UPTIME:-100}"
    fi ;;
postqueue)
    printf '3Pq4Yh1b7Zz9xyV  1024 Tue Nov  4 10:00:00  sender@example.org\n                                         rcpt@example.net\n\n'
    echo '-- 50 Kbytes in 1200 Requests.' ;;
postconf) ;;
sshd) ;;
httpd)
    case $1 in -v) echo 'Server version: Apache/2.4.62 (Unix)' ;; -V) echo 'Server MPM:     event' ;; esac ;;
php-fpm8.2) ;;
curl)
    [[ $SCENARIO == apps ]] || exit 7
    case $args in
        *15692/metrics*)
            cat <<'METRICS'
# TYPE rabbitmq_build_info untyped
rabbitmq_build_info{rabbitmq_version="3.13.7",erlang_version="26.2"} 1
rabbitmq_erlang_uptime_seconds 200000
rabbitmq_resident_memory_limit_bytes 1073741824
rabbitmq_process_resident_memory_bytes 268435456
rabbitmq_disk_space_available_bytes 53687091200
rabbitmq_disk_space_available_limit_bytes 50000000
rabbitmq_alarms_memory_used_watermark 0
rabbitmq_process_open_fds 900
rabbitmq_process_max_fds 1024
rabbitmq_connections 12
rabbitmq_queue_messages{queue="a"} 40
rabbitmq_queue_messages{queue="b"} 2
METRICS
            ;;
        *8123*)
            case $args in
                *'version()'*) echo 24.8.4.13 ;;
                *'uptime()'*) echo 200000 ;;
                *system.metrics*) printf 'TCPConnection\t90\nHTTPConnection\t5\nQuery\t3\nMemoryTracking\t1073741824\n' ;;
                *system.events*) printf 'RejectedInserts\t7\n' ;;
                *server_settings*) printf 'max_connections\t100\nmax_concurrent_queries\t100\nmax_server_memory_usage\t0\nmax_server_memory_usage_to_ram_ratio\t0.9\n' ;;
            esac ;;
        *8086/ping*) printf 'HTTP/1.1 204 No Content\r\nX-Influxdb-Version: 1.8.10\r\n\r\n' ;;
        *8086/metrics*) echo 'go_memstats_alloc_bytes 104857600' ;;
        *9283/metrics*)
            printf 'ceph_health_status 1\nceph_cluster_total_bytes 1099511627776\nceph_cluster_total_used_bytes 549755813888\n'
            printf 'ceph_osd_up{ceph_daemon="osd.0"} 1\nceph_osd_up{ceph_daemon="osd.1"} 1\nceph_osd_in{ceph_daemon="osd.0"} 1\nceph_osd_in{ceph_daemon="osd.1"} 1\n' ;;
        *2019/metrics*) printf 'caddy_build_info{version="v2.8.4"} 1\nprocess_open_fds 12\nprocess_max_fds 1024\ngo_memstats_alloc_bytes 1048576\n' ;;
        *squid-internal-mgr/info*)
            printf 'Squid Object Cache: Version 5.7\nUP Time:\t200000.123 seconds\nFile descriptor usage for squid:\n\tMaximum number of file descriptors:   1024\n\tNumber of file desc currently in use:  800\nInternal Data Structures:\n\tStorage Mem capacity:\t 12.5%% used, 87.5%% free\n' ;;
        *) exit 7 ;;
    esac ;;
iptables) echo '-P INPUT ACCEPT' ;;
ip6tables) ;;
apt-get) printf 'Inst libssl3 [3.0] (3.1 Ubuntu:24.04/noble-security [amd64])\nInst vim [1] (2 Ubuntu:24.04/noble-updates [amd64])\n' ;;
crontab) echo '0 3 * * * /usr/local/bin/cleanup.sh' ;;
last) echo 'reboot   system boot  6.8.0 Wed Nov  4 10:00   still running' ;;
ps)
    if [[ $SCENARIO == apps ]]; then
        case $args in
            *'etimes=,comm='*) printf '%s nginx\n%s gunicorn\n%s uwsgi\n%s httpd\n' "${FAKE_UPTIME:-200000}" "${FAKE_UPTIME:-200000}" "${FAKE_UPTIME:-200000}" "${FAKE_UPTIME:-200000}"; exit 0 ;;
            *'etimes= -p'*) echo "${FAKE_UPTIME:-200000}"; exit 0 ;;
            *'pid=,ppid=,pcpu=,rss=,comm='*)
                printf '100 1 0.0 20000 gunicorn\n101 100 40.0 50000 gunicorn\n102 100 60.0 70000 gunicorn\n'
                printf '200 1 0.0 20000 uwsgi\n201 200 10.0 30000 uwsgi\n'
                exit 0 ;;
            *'pid=,rss=,comm='*) printf '300 400000 java\n310 90000 node\n'; exit 0 ;;
        esac
    fi
    if [[ $SCENARIO == fpm && $args == *'pid=,rss=,args='* ]]; then echo '100 2000 php-fpm8.2: pool www'; exit 0; fi
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
