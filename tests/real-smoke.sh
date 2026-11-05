#!/bin/bash
# Runs every view on a real system. Each must exit 0 with no shell errors, and the script's
# file list must stay the same as before: the audit promises to write nothing.
script=$(cd "$(dirname "$0")/.." && pwd)/linux-host-audit.sh
bad=0

printf 'bash %s on: ' "$BASH_VERSION"
grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null || echo unknown

snapshot() { find /etc /usr/local /root /home -xdev -type f 2>/dev/null | sort; }
before=$(snapshot)

for view in --overview --problems --apps --network --containers --k8s --web --db --security \
    --logs --errors --panel --tune --jobs --resources --learn --report --json --metrics --help --version '--text --found-only' \
    '--text --found-only --inventory'; do
    # shellcheck disable=SC2086 # the last entry carries two words on purpose
    out=$(NO_COLOR=1 bash "$script" $view 2>&1 </dev/null)
    rc=$?
    if ((rc != 0)); then
        printf 'FAIL %s: exit %s\n' "$view" "$rc"
        printf '%s\n' "$out" | tail -n 8
        bad=1
    fi
    if printf '%s\n' "$out" | grep -E 'command not found|syntax error|unbound variable|bad substitution|invalid option|integer expression|arithmetic'; then
        printf 'FAIL %s: shell error above\n' "$view"
        bad=1
    fi
done

NO_COLOR=1 bash "$script" --check </dev/null
rc=$?
if ((rc > 2)); then printf 'FAIL --check: exit %s\n' "$rc"; bad=1; fi

if [[ $(snapshot) != "$before" ]]; then
    echo 'FAIL: files appeared or vanished during the run:'
    diff <(printf '%s\n' "$before") <(snapshot) | head -n 20
    bad=1
fi

((bad == 0)) && echo 'smoke OK'
exit "$bad"
