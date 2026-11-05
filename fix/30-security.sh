# Security fixes. Anything that could lock you out runs under the dead-man timer.

fx_ssh_port() { awk '$5 == "sshd" || $5 == "ssh" { print $2; exit }' <<< "$NET_ROWS"; }

fx_public_ports() { awk '$3 == "public" { print $2 "/" $1 }' <<< "$NET_ROWS" | sort -u; }

fx_remote_clients() {
    run_t 5 ss -Htn state established "( sport = :$1 )" 2>/dev/null |
        awk '{ print $NF }' | grep -v '^127\.\|^\[::1\]' | sed 's/:[0-9]*$//' | sort -u | head -n 5 | tr '\n' ' '
}

dx_no_firewall() {
    local ssh count
    ssh=$(fx_ssh_port)
    count=$(fx_public_ports | wc -l | tr -d ' ')
    FX_CAUSE="No firewall is filtering traffic, so all $count public ports are reachable."
    if [[ -d /usr/local/cpanel ]]; then
        FX_MODE=never
        FX_STEPS=('cPanel needs many ports. Use WHM > Security Center, or install CSF, which knows them.')
        return 0
    fi
    if [[ -z $ssh ]]; then
        FX_MODE=never FX_CAUSE+=' The SSH port could not be found, so a firewall could lock you out.'
        return 0
    fi
    if has ufw; then FX_TOOL=ufw
    elif has firewall-cmd; then FX_TOOL=firewalld
    else
        FX_STEPS=('Install ufw (Debian, Ubuntu) or firewalld (RHEL family), then run this fix again.')
        return 0
    fi
    FX_MODE=auto FX_RISK=high FX_LOCKOUT=yes
    FX_PLAN=("Turn on $FX_TOOL." "Allow every port that is public today, SSH ($ssh) first, so nothing changes for working services."
        'New ports will be closed from now on.' 'Then close the ports you do not want one by one.')
}
ap_no_firewall() {
    local port ssh
    ssh=$(fx_ssh_port)
    if [[ $FX_TOOL == ufw ]]; then
        fx_undo 'ufw --force disable'
        fx_run ufw allow "$ssh/tcp" || return 1
        while read -r port; do [[ -z $port ]] || fx_run ufw allow "$port"; done <<< "$(fx_public_ports)"
        fx_run ufw --force enable
    else
        fx_undo 'systemctl disable --now firewalld'
        fx_run systemctl enable --now firewalld || return 1
        fx_run firewall-cmd --permanent --add-port="$ssh/tcp" || return 1
        while read -r port; do [[ -z $port ]] || fx_run firewall-cmd --permanent --add-port="$port"; done <<< "$(fx_public_ports)"
        fx_run firewall-cmd --reload
    fi
}
ck_no_firewall() {
    if [[ $FX_TOOL == ufw ]]; then [[ $(ufw status 2>/dev/null) == *'Status: active'* ]]
    else [[ $(firewall-cmd --state 2>/dev/null) == running ]]
    fi
}

dx_ssh_root_password() {
    local keys=/root/.ssh/authorized_keys
    FX_CAUSE='Root can log in with only a password, the main target of SSH bots.'
    if [[ ! -s $keys ]] || ! grep -qE '^[^#]*(ssh-|ecdsa-|sk-)' "$keys"; then
        FX_MODE=never
        FX_CAUSE+=' Root has no SSH key, so turning passwords off would lock you out.'
        FX_STEPS=('Add your key first: ssh-copy-id root@THIS_SERVER' 'Check that the key logs in, then run this fix again.')
        return 0
    fi
    FX_MODE=auto FX_RISK=high FX_LOCKOUT=yes
    FX_PLAN=('Set PermitRootLogin prohibit-password. Root keeps logging in with its key.'
        'Test the SSH config before loading it. Reload keeps open sessions.')
}
ap_ssh_root_password() {
    local unit=sshd file=/etc/ssh/sshd_config
    [[ $(run_t 3 systemctl is-active ssh 2>/dev/null) != active ]] || unit=ssh
    if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' "$file"; then
        # First match wins in sshd_config.d, so sort this file early.
        printf 'PermitRootLogin prohibit-password\n' | fx_write /etc/ssh/sshd_config.d/00-linux-host-audit.conf || return 1
    else
        sed -E 's/^[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin prohibit-password/' "$file" | fx_write "$file" || return 1
        grep -qE '^PermitRootLogin' "$file" || return 1
    fi
    fx_quote systemctl reload "$unit"
    fx_undo "$REPLY"
    sshd -t || return 1
    fx_run systemctl reload "$unit"
}
ck_ssh_root_password() { [[ $(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2 }') == prohibit-password ]]; }

dx_empty_passwords() {
    local names
    names=$(awk -F: '$2 == "" { printf "%s ", $1 }' /etc/shadow 2>/dev/null | clean)
    FX_CAUSE="These accounts have no password: ${names:-none}."
    [[ -n $names ]] || return 0
    FX_MODE=auto FX_RISK=medium
    FX_PLAN=("Lock them: passwd -l. SSH keys keep working unless the account is expired.")
}
ap_empty_passwords() {
    local name
    for name in $(awk -F: '$2 == "" { print $1 }' /etc/shadow); do
        fx_quote passwd -d "$name"
        fx_undo "$REPLY"
        fx_run passwd -l "$name" || return 1
    done
}
ck_empty_passwords() { ! awk -F: '$2 == "" { found = 1 } END { exit !found }' /etc/shadow; }

# Blocks one port from outside, and leaves this machine's own access working.
fx_block_plan() {
    local port=$1 label=$2 clients
    # Silence from a missing tool must not count as "nobody is connected".
    if ! has ss || ! run_t 5 ss -Htn state established >/dev/null 2>&1; then
        FX_STEPS=("Cannot tell who uses port $port on this system, so it stays open." "Check clients by hand, then block port $port.")
        return 0
    fi
    clients=$(fx_remote_clients "$port")
    if [[ -n $clients ]]; then
        FX_CAUSE+=" Remote clients are connected right now: $clients"
        FX_STEPS=('Do not close it until those clients move. Then limit access to their addresses.' "ss -tn '( sport = :$port )'")
        return 0
    fi
    if ! has iptables; then
        FX_STEPS=("Set the service to listen on 127.0.0.1, or block port $port in your firewall.")
        return 0
    fi
    FX_MODE=auto FX_RISK=medium FX_PORT=$port
    FX_PLAN=("Block port $port from outside. Nothing is connected to it from another machine now." "Local apps keep using $label.")
    FX_STEPS=("This rule disappears at reboot. For good, make $label listen on 127.0.0.1 only.")
}
fx_block_apply() {
    fx_quote iptables -D INPUT -p tcp --dport "$FX_PORT" '!' -s 127.0.0.1 -j DROP
    fx_undo "$REPLY"
    fx_run iptables -I INPUT -p tcp --dport "$FX_PORT" '!' -s 127.0.0.1 -j DROP
}
fx_block_check() { iptables -S INPUT 2>/dev/null | grep -q -- "--dport $FX_PORT .*-j DROP"; }

dx_docker_api_open() {
    FX_CAUSE='The Docker API listens without TLS. Whoever reaches it has root here.'
    fx_block_plan 2375 Docker
    FX_STEPS+=('Remove tcp://0.0.0.0:2375 from dockerd options or daemon.json, then restart Docker in a quiet moment.')
}
ap_docker_api_open() { fx_block_apply; }
ck_docker_api_open() { fx_block_check; }
dx_db_exposed() {
    port_name "$1"
    FX_CAUSE="$REPLY listens on all interfaces, and no firewall was seen."
    fx_block_plan "$1" "$REPLY"
}
ap_db_exposed() { fx_block_apply; }
ck_db_exposed() { fx_block_check; }
dx_redis_open() {
    FX_CAUSE="$1 has no password and is public. Anyone can read it, or use it to take over the server."
    fx_block_plan 6379 "$1"
    FX_STEPS+=('Then set bind 127.0.0.1 and requirepass in its config.')
}
ap_redis_open() { fx_block_apply; }
ck_redis_open() { fx_block_check; }

dx_updates_security() {
    local list hold
    FX_STEPS=('apt list --upgradable')
    if ! has apt-get; then
        FX_CAUSE='Security updates are waiting.'
        FX_STEPS=('dnf updateinfo list security' 'dnf upgrade --security')
        return 0
    fi
    list=$(run_t 15 apt-get -s -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade 2>/dev/null |
        awk '/^Inst .*[Ss]ecurity/ { print $2 }')
    # Databases, engines and kernels restart with real consequences, so a person picks the moment.
    hold=$(grep -E '^(mysql|mariadb|percona|postgresql|redis|valkey|mongodb|docker|containerd|kube|k3s|linux-)' <<< "$list" | tr '\n' ' ')
    FX_PACKAGES=$(grep -vE '^(mysql|mariadb|percona|postgresql|redis|valkey|mongodb|docker|containerd|kube|k3s|linux-)' <<< "$list" | tr '\n' ' ')
    FX_CAUSE="Waiting: $(tr '\n' ' ' <<< "$list" | cut -c1-160)"
    [[ -z $hold ]] || FX_STEPS+=("Update these at a planned moment, they restart key services: $hold")
    if [[ -n ${FX_PACKAGES// /} ]]; then
        FX_MODE=auto FX_RISK=medium FX_UNDOABLE=no
        FX_PLAN=("Install security updates: $FX_PACKAGES" 'Keep your existing config files.' 'Services that restart are checked afterwards.')
    fi
}
ap_updates_security() {
    # shellcheck disable=SC2086 # package names are split on purpose
    fx_run env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get -y -o Dpkg::Options::=--force-confold \
        install --only-upgrade $FX_PACKAGES
}
ck_updates_security() {
    ! run_t 15 apt-get -s -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade 2>/dev/null |
        grep -qF "Inst ${FX_PACKAGES%% *} "
}
