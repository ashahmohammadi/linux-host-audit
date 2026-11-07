#!/bin/bash
# The real break-and-fix tests inside a booted system, one per release, so the host stays untouched.
# Run: bash tests/fix-distros.sh [image ...]. Needs Docker. Prints passes and failures per image.
here=$(cd "$(dirname "$0")/.." && pwd)
images=("$@")
((${#images[@]})) || images=(almalinux/8-init almalinux/9-init almalinux/10-init ubuntu:20.04 ubuntu:22.04 ubuntu:24.04 ubuntu:26.04)
# ufw on Ubuntu 20.04 needs these, and a container cannot load them for itself.
modprobe -a ip6_tables ip6table_filter 2>/dev/null
bad=0
for image in "${images[@]}"; do
    name=lha-fix-${image//[^a-z0-9]/-}
    docker rm -f "$name" >/dev/null 2>&1
    case $image in
        ubuntu:*)
            printf 'FROM %s\nRUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus >/dev/null\nCMD ["/sbin/init"]\n' "$image" |
                docker build -q -t "$name" - >/dev/null || { echo "FAIL $image could not build"; bad=1; continue; }
            run=$name ;;
        *) run=$image ;;
    esac
    docker run -d --name "$name" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        --tmpfs /tmp --tmpfs /run --tmpfs /run/lock -v "$here:/w:ro" "$run" >/dev/null
    sleep 8
    docker exec "$name" sh -c 'getent hosts deb.debian.org >/dev/null || getent hosts repo.almalinux.org >/dev/null' || { echo "FAIL $image has no network, so this run proves nothing"; bad=1; docker rm -f "$name" >/dev/null 2>&1; continue; }
    docker exec "$name" sh -c '
        if command -v apt-get >/dev/null; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq; apt-get install -y -qq nginx ufw mariadb-server redis-server openssh-server cron curl procps iproute2 >/dev/null
        else
            # The timer holds the dnf lock on first boot, and one fixed mirror is steadier behind a proxy.
            systemctl stop dnf-makecache.timer dnf-makecache.service >/dev/null 2>&1
            sed -i -E "s|^mirrorlist=|#mirrorlist=|; s|^# ?baseurl=|baseurl=|" /etc/yum.repos.d/*.repo
            printf "fastestmirror=0
timeout=60
retries=4
" >> /etc/dnf/dnf.conf
            timeout 3000 dnf install -y -q nginx firewalld mariadb-server openssh-server cronie procps-ng iproute iptables python3 >/dev/null
            timeout 900 dnf install -y -q redis >/dev/null 2>&1 || timeout 900 dnf install -y -q valkey >/dev/null 2>&1
            systemctl enable --now crond >/dev/null 2>&1
        fi
        ssh-keygen -A >/dev/null 2>&1
        systemctl start sshd ssh >/dev/null 2>&1
        true' > "/tmp/$name.install" 2>&1
    timeout -s KILL 500 docker exec -e LHA_I_AM_DISPOSABLE=yes "$name" bash /w/tests/fix-real.sh > "/tmp/$name.log" 2>&1
    rc=$?
    printf '%-22s rc=%s %s\n' "$image" "$rc" "$(tail -n 1 "/tmp/$name.log")"
    grep -E '^FAIL' "/tmp/$name.log" | sed 's/^/    /'
    ((rc == 0)) || bad=1
    ((rc == 0)) || docker exec "$name" sh -c 'for f in /var/lib/lha-test/runs/* /var/lib/linux-host-audit/runs/*; do :; done; ls -dt /var/lib/lha-test/runs/* | head -n 1 | xargs -I{} tail -n 25 {}/journal.log' 2>/dev/null | sed 's/^/    | /'
    docker rm -f "$name" >/dev/null 2>&1
done
exit "$bad"
