#!/bin/bash
# The listener table read from /proc must agree with ss, which is the reference on a real host.
script=$(cd "$(dirname "$0")/.." && pwd)/linux-host-audit.sh
# shellcheck disable=SC1090
source <(sed '$d' "$script")
export LC_ALL=C
ui_colors

python3 -m http.server 18099 --bind 127.0.0.1 >/dev/null 2>&1 &
server=$!
sleep 2

from_proc=$(proc_listeners)
ours=$(awk '$1 == "tcp" { print $2 }' <<< "$from_proc" | sort -u)
theirs=$(ss -lnt | awk '$1 == "LISTEN" { n = split($4, a, ":"); print a[n] }' | sort -u)
printf 'From /proc:\n%s\n\nFrom ss:\n%s\n' "$ours" "$theirs"
kill "$server"

bad=0
if [[ $ours != "$theirs" ]]; then echo 'FAIL: the two lists differ'; bad=1; fi
if ! grep -q '^tcp 18099 127.0.0.1 python3 ' <<< "$from_proc"; then echo 'FAIL: no process name for the test port'; bad=1; fi
exit "$bad"
