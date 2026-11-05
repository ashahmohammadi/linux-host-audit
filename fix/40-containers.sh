# Containers and Kubernetes. Reads logs and states, and restarts only what is already broken.

fx_engine() {
    FX_ENGINE=docker
    has docker || FX_ENGINE=podman
}

# Last lines a container printed. They can hold private data, so they stay on this screen.
fx_ct_logs() { run_t 8 "$FX_ENGINE" logs --tail "${2:-6}" "$1" 2>&1 | clean | cut -c1-140; }

fx_ct_reason() {
    local name=$1 log lower
    log=$(fx_ct_logs "$name" 12)
    lower=$(tr 'A-Z' 'a-z' <<< "$log")
    case $lower in
        *'no space left'*) FX_CAUSE+=' The logs say the disk is full.' ;;
        *'address already in use'*) FX_CAUSE+=' A port it needs is already taken.' ;;
        *'permission denied'*) FX_CAUSE+=' A file or volume has the wrong owner.' ;;
        *'connection refused'*|*'could not connect'*|*'name or service not known'*|*'temporary failure in name'*)
            FX_CAUSE+=' It cannot reach something it depends on, such as its database.' ;;
        *'out of memory'*|*'cannot allocate'*) FX_CAUSE+=' It ran out of memory.' ;;
        *'no such file'*|*'not found'*) FX_CAUSE+=' A file or command it needs is missing, often a bad image or mount.' ;;
        *'password'*|*'authentication failed'*|*'access denied'*) FX_CAUSE+=' Its credentials are being rejected.' ;;
    esac
    FX_STEPS+=("Last log line: $(tail -n 1 <<< "$log")" "$FX_ENGINE logs --tail 100 $name")
}

dx_container_unhealthy() {
    local name=$1 probe
    fx_engine
    probe=$(run_t 5 "$FX_ENGINE" inspect -f '{{range .State.Health.Log}}{{.ExitCode}} {{end}}' "$name" 2>/dev/null)
    FX_CAUSE="Its health check keeps failing (recent exit codes: ${probe:-unknown})."
    fx_ct_reason "$name"
    FX_MODE=auto FX_RISK=medium FX_UNDOABLE=no FX_EXPECT_GONE="container $name"
    FX_PLAN=("Restart container $name once. Its data volumes stay.")
}
ap_container_unhealthy() { fx_run "$FX_ENGINE" restart "$1"; }
ck_container_unhealthy() {
    local i state
    for ((i = 0; i < 12; i++)); do
        state=$(run_t 5 "$FX_ENGINE" inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)
        [[ $state != healthy ]] || return 0
        sleep 5
    done
    return 1
}

# A restart cannot help these: the same thing happens again, so explain it precisely.
dx_container_restarting() {
    fx_engine
    FX_CAUSE='It crashes right after every start.'
    fx_ct_reason "$1"
}
dx_container_exit_error() {
    fx_engine
    FX_CAUSE="The program inside exited with an error."
    fx_ct_reason "$1"
    FX_STEPS+=("Start it again only after fixing the cause: $FX_ENGINE start $1")
}
dx_container_killed() {
    local oom
    fx_engine
    oom=$(run_t 5 "$FX_ENGINE" inspect -f '{{.State.OOMKilled}}' "$1" 2>/dev/null)
    if [[ $oom == true ]]; then FX_CAUSE='It was killed for using too much memory.'
    else FX_CAUSE='It was force-stopped (SIGKILL), not by the memory limit. Often docker stop timing out, or a person.'
    fi
    FX_STEPS=("$FX_ENGINE inspect -f '{{.HostConfig.Memory}}' $1" "$FX_ENGINE start $1")
}
dx_container_oom() {
    local limit
    fx_engine
    limit=$(run_t 5 "$FX_ENGINE" inspect -f '{{.HostConfig.Memory}}' "$1" 2>/dev/null)
    if [[ $limit == 0 ]]; then FX_CAUSE='No memory limit is set, so the host itself ran out of memory.'
    else FX_CAUSE="It reached its limit of $(fx_bytes "$limit")."
    fi
    FX_STEPS=("$FX_ENGINE stats --no-stream $1" "Raise its limit in compose or: $FX_ENGINE update --memory 1g --memory-swap 2g $1")
}
dx_container_restart_count() {
    fx_engine
    FX_CAUSE='It runs now, but it has crashed many times.'
    fx_ct_reason "$1"
}
dx_container_dead() {
    fx_engine
    FX_CAUSE='Docker could not stop or remove it. Often a stuck mount or storage trouble.'
    FX_STEPS=("$FX_ENGINE inspect $1" 'journalctl -u docker -n 50' "Check the volume is unused, then: $FX_ENGINE rm $1")
}
dx_container_privileged() {
    fx_engine
    FX_CAUSE='Privileged mode gives it almost full control of the host.'
    FX_MODE=never
    FX_STEPS=('Some tools need this. Find out which capability it needs, then use --cap-add instead.' "$FX_ENGINE inspect -f '{{.HostConfig.CapAdd}}' $1")
}

dx_container_log_large() {
    fx_engine
    FX_LOG_FILE=$(ls -S /var/lib/docker/containers/*/*-json.log 2>/dev/null | head -n 1)
    FX_CAUSE="Biggest log: ${FX_LOG_FILE:-not found}. Docker does not rotate logs by default."
    FX_STEPS=('Stop it coming back: set "log-opts": {"max-size": "100m", "max-file": "3"} in /etc/docker/daemon.json.' 'That applies to containers created afterwards.')
    [[ -n $FX_LOG_FILE ]] || return 0
    FX_MODE=auto FX_RISK=medium FX_UNDOABLE=no
    FX_PLAN=('Empty this log file. The container keeps running. Its old log lines are lost.')
    FX_SIZE_BEFORE=$(stat -c %s "$FX_LOG_FILE")
}
ap_container_log_large() { fx_run truncate -s 0 "$FX_LOG_FILE"; }
ck_container_log_large() { (($(stat -c %s "$FX_LOG_FILE") < FX_SIZE_BEFORE)); }

dx_engine_no_access() { FX_CAUSE='This user may not talk to the engine.'; FX_STEPS=('Run as root, or add the user to the docker group.'); }
dx_engine_hung() {
    FX_CAUSE='The engine does not answer. Usually storage trouble or a stuck container.'
    FX_STEPS=("journalctl -u $1 -n 50" 'dmesg | tail -30' "A restart stops containers without live-restore: systemctl restart $1")
}

# Kubernetes
fx_ku() { kube_find; ku "$@"; }

dx_kube_pods_unhealthy() {
    local line ns pod status reason
    FX_CAUSE='Each pod below says why it is not healthy.'
    FX_STEPS=()
    while read -r line; do
        [[ -n $line ]] || continue
        read -r ns pod _ status _ <<< "$line"
        case $status in
            CrashLoopBackOff) reason="crashes on start: kubectl logs $pod -n $ns --previous" ;;
            ImagePullBackOff|ErrImagePull) reason="image cannot be downloaded: check its name, tag and registry secret" ;;
            Pending) reason="no node can take it: kubectl describe pod $pod -n $ns, read Events" ;;
            OOMKilled) reason='out of memory: raise resources.limits.memory' ;;
            CreateContainerConfigError) reason='a secret or configmap it needs is missing' ;;
            Evicted) reason='the node ran short of resources' ;;
            *) reason="kubectl describe pod $pod -n $ns" ;;
        esac
        FX_STEPS+=("$ns/$pod $status: $reason")
    done <<< "$(head -n 12 <<< "$K_BAD_ROWS")"
}
dx_kube_node_notready() {
    local conditions
    conditions=$(fx_ku get node "$1" -o 'jsonpath={range .status.conditions[*]}{.type}={.status}: {.message}{"\n"}{end}' | clean | grep -v '=False' | head -n 3 | cut -c1-120)
    FX_CAUSE="Node conditions: ${conditions:-unknown}."
    FX_STEPS=("On that node: systemctl status kubelet" "journalctl -u kubelet -n 50 --no-pager" 'Also check its disk, memory and container runtime.')
    if [[ $1 == "$H_NAME" && $(run_t 3 systemctl is-active kubelet 2>/dev/null) != active ]]; then
        dx_service_failed kubelet.service
        FX_UNIT=kubelet.service
    fi
}
ap_kube_node_notready() { ap_service_failed "$FX_UNIT"; }
ck_kube_node_notready() { ck_service_failed "$FX_UNIT"; }
dx_kube_node_memory() { FX_CAUSE='The kubelet reports memory pressure, and will evict pods.'; FX_STEPS=("kubectl top pods -A --sort-by=memory" "kubectl describe node $1"); }
dx_kube_node_disk() { FX_CAUSE='The kubelet reports disk pressure, and will evict pods and remove images.'; FX_STEPS=('Run the disk fix on that node.' 'crictl rmi --prune'); }
dx_kube_deployments_unready() { FX_CAUSE='Deployments have fewer ready pods than requested.'; FX_STEPS=('kubectl get deploy -A' 'kubectl rollout status deploy/NAME -n NS' 'kubectl rollout undo deploy/NAME -n NS undoes a bad release.'); }
dx_kube_pvc_unbound() { FX_CAUSE='A storage claim has no volume.'; FX_STEPS=('kubectl get pvc -A' 'kubectl describe pvc NAME -n NS' 'kubectl get storageclass'); }
dx_kube_pods_restarting() { FX_CAUSE='These pods keep restarting.'; FX_STEPS=('kubectl logs POD -n NS --previous' 'kubectl get events -A --sort-by=.lastTimestamp | tail -20'); }
dx_kube_api_down() {
    FX_CAUSE='kubectl cannot reach the API server.'
    FX_STEPS=('systemctl status kubelet k3s rke2-server' 'crictl ps -a | grep -E "apiserver|etcd"' 'df -h /var/lib/etcd' 'kubeadm certs check-expiration')
}
dx_kube_cert_expiring() {
    FX_CAUSE="$1 expires within 30 days."
    FX_MODE=never
    FX_STEPS=('kubeadm: kubeadm certs renew all, then restart the control-plane static pods one at a time.' 'k3s or RKE2: restart the service, which rotates certificates near expiry.')
}
dx_kube_no_client() { FX_CAUSE='No kubectl on this machine.'; FX_STEPS=('crictl ps' 'Run this tool on a control-plane node.'); }
dx_kube_no_credentials() { FX_CAUSE='Normal on a worker node.'; FX_STEPS=('Run this tool on a control-plane node.'); }
