# Linux Host Audit

One command that explains a Linux server from zero to one hundred: what it is, whether it is
healthy, what runs on it, what is exposed, and what to look at next. Every section also teaches
the real commands behind it.

Read-only. It installs nothing, writes no files, and sends nothing off the server.
It never prints passwords, process arguments, container environments or Kubernetes secrets.

## Run it

With the script on the server:

```bash
sudo bash linux-host-audit.sh
```

Without copying anything, from your own machine:

```bash
ssh root@SERVER 'bash -s -- --report' < linux-host-audit.sh
```

On a production server, at the lowest priority:

```bash
ssh root@SERVER 'nice -n 19 ionice -c3 bash -s -- --report' < linux-host-audit.sh
```

Server with no internet: run `bash make-paste.sh`, then paste the whole of
`paste-to-server.txt` into the server's terminal. Replace `| bash` on its first line
with `| sudo bash` if you are not root.

## What it covers

Overview, problems with fixes, applications (found by port, service and process, so unknown apps
appear too), ports and firewall, Docker, Podman, LXD, Incus, Proxmox, libvirt, Kubernetes (k8s, k3s,
k0s, RKE2, MicroK8s, OpenShift), websites, domains and SSL, databases and caches, security, logs,
scheduled jobs, backups, a live monitor, and a guided tour.

`--help` lists every view. `--check` prints one status line and exits 0, 1 or 2 for cron or monitoring.

## Limits

- Bash is required, so Alpine needs `apk add bash`.
- Without root, some sections are partial, and the report says so.
- Pending updates are not checked on dnf and yum, because those tools write to their logs.
- Database details need passwordless local access. It never asks for a password.
- `kubectl` keeps its own small cache in `~/.kube`, which is the one write this tool can cause.
- Only MySQL and Redis are queried for details. Others show running or listening only.
- A clean report means these checks found nothing. It does not prove a server is secure.

## Tests

`bash tests/run.sh` runs simulated servers with fake `docker`, `kubectl`, `ss` and other tools.
