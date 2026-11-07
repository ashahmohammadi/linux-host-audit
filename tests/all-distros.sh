#!/bin/bash
# Every view on many Linux releases, one container each. Prints one line per image and a summary.
# Run: bash tests/all-distros.sh [image ...]. Needs Docker. Changes nothing outside the containers.
here=$(cd "$(dirname "$0")/.." && pwd)
images=("$@")
if ((${#images[@]} == 0)); then
    images=(
        almalinux:8 almalinux:8-minimal almalinux:8.10 almalinux:9 almalinux:9-minimal almalinux:9.6
        almalinux:10 almalinux:10-minimal almalinux:10-kitten almalinux/8-base almalinux/9-base almalinux/10-base
        almalinux/8-init almalinux/9-init almalinux/10-init
        ubuntu:12.04 ubuntu:14.04 ubuntu:16.04 ubuntu:18.04 ubuntu:20.04 ubuntu:22.04 ubuntu:24.04 ubuntu:24.10
        ubuntu:25.04 ubuntu:25.10 ubuntu:26.04 ubuntu:devel ubuntu:rolling
        debian:8 debian:9 debian:10 debian:11 debian:12 debian:13 debian:unstable
        rockylinux:8 rockylinux:9 rockylinux/rockylinux:10 oraclelinux:7 oraclelinux:8 oraclelinux:9 oraclelinux:10
        centos:6 centos:7 quay.io/centos/centos:stream9 quay.io/centos/centos:stream10
        fedora:40 fedora:42 fedora:latest fedora:rawhide amazonlinux:2 amazonlinux:2023
        opensuse/leap:15 opensuse/leap:16.0 opensuse/tumbleweed archlinux:latest manjarolinux/base
        alpine:3.10 alpine:3.20 alpine:latest alpine:edge kalilinux/kali-rolling gentoo/stage3 voidlinux/voidlinux
        mageia:9 photon:5.0 linuxmintd/mint22-amd64 devuan/devuan:daedalus clearlinux:latest bash:3.2 bash:4.0
    )
fi
ok=0 bad=0 skip=0
for image in "${images[@]}"; do
    if ! timeout 180 docker pull -q "$image" >/dev/null 2>&1; then
        printf 'SKIP %-38s image not available\n' "$image"
        ((skip += 1))
        continue
    fi
    # Docker ignores a plain TERM here, so a hang must be killed from outside and named a failure.
    ( sleep 300; docker rm -f lha-distro >/dev/null 2>&1 ) &
    watchdog=$!
    log=$(docker run --rm --name lha-distro -v "$here:/w:ro" --entrypoint sh "$image" -c '
        if command -v apk >/dev/null && ! command -v bash >/dev/null; then apk add -q bash; fi
        if ! command -v bash >/dev/null; then echo NOBASH; exit 42; fi
        if ! command -v awk >/dev/null; then
            bash /w/linux-host-audit.sh --overview; test $? = 3 || exit 1
            echo NOAWK; exit 0
        fi
        bash /w/tests/real-smoke.sh && bash /w/tests/parse-real.sh' 2>&1)
    rc=$?
    kill "$watchdog" 2>/dev/null
    if ((rc == 0)); then
        note=$(grep -qx NOAWK <<< "$log" && printf 'no awk: stops with a clear message')
        printf 'ok   %-38s %s\n' "$image" "$note"
        ((ok += 1))
    else
        printf 'FAIL %-38s exit %s\n' "$image" "$rc"
        tail -n 8 <<< "$log" | sed 's/^/     /'
        ((bad += 1))
    fi
    docker rmi "$image" >/dev/null 2>&1
done
printf '%d ok, %d failed, %d not available\n' "$ok" "$bad" "$skip"
((bad == 0))
