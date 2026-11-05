#!/bin/bash
# Parsers on the real awk, sed and grep of each distribution. mawk 1.3.3 and busybox fail quietly
# on what gawk accepts, so a run with no error proves nothing. Runs inside a disposable container.
if [[ ! -f /.dockerenv ]]; then
    echo 'Refusing to run: this writes test files under /etc and /var/log. It belongs in a container.'
    exit 3
fi
script=$(cd "$(dirname "$0")/.." && pwd)/linux-host-audit.sh
bad=0
want() {
    if grep -qF -- "$2" <<< "$1"; then printf 'ok    %s\n' "$2"
    else printf 'FAIL  missing: %s\n' "$2"; bad=1
    fi
}
reject() {
    if grep -qF -- "$2" <<< "$1"; then printf 'FAIL  must not appear: %s\n' "$2"; bad=1
    else printf 'ok    not shown: %s\n' "$2"
    fi
}

mkdir -p /etc/nginx/conf.d /var/log/nginx
printf 'server {\n    server_name real-parse.example.org;\n    fastcgi_cache one;\n}\n' > /etc/nginx/conf.d/parse.conf
printf 'server_name   tabbed.example.net;\n' >> /etc/nginx/conf.d/parse.conf

out=$(NO_COLOR=1 bash "$script" --web 2>&1)
want "$out" 'real-parse.example.org'
want "$out" 'tabbed.example.net'

out=$(NO_COLOR=1 bash "$script" --text --found-only 2>&1)
want "$out" 'NGINX FastCGI cache'
want "$out" 'CONFIG-FOUND'

out=$(NO_COLOR=1 bash -c '
    eval "$(sed "\$d" "$1")"
    export LC_ALL=C
    ui_colors
    {
        printf "2026/11/04 10:00:01 [error] 1#1: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 1.1.1.1\n"
        printf "2026/11/04 10:00:02 [error] 1#1: *2 connect() failed (111: Connection refused) while connecting to upstream, client: 2.2.2.2\n"
        printf "2026/11/04 10:00:03 [notice] 1#1: a calm line\n"
        printf "2026/11/04 10:00:04 [crit] 1#1: login with password=hunter9 and token: abc\n"
    } | err_group "\[(emerg|alert|crit|error)\]"
    proc_listeners | head -n 3
' _ "$script" 2>&1)
printf '%s\n' "$out"
want "$out" '2x'
want "$out" 'The app behind the web server is down'
want "$out" 'password=***'
reject "$out" 'hunter9'
reject "$out" 'a calm line'
reject "$out" 'syntax error'
reject "$out" 'regular expression'

exit "$bad"
