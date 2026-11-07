# Linux Host Audit

One command that explains a Linux server from zero to one hundred: what it is, whether it is
healthy, what runs on it, what is exposed, and what to look at next. Every section also teaches
the real commands behind it.

Read-only. It installs nothing, writes no files, and sends nothing off the server.
It never prints passwords, process arguments, container environments or Kubernetes secrets.

## Run it

One line, on any Linux server:

```bash
curl -fsSL https://raw.githubusercontent.com/ashahmohammadi/linux-host-audit/main/linux-host-audit.sh | sudo bash
```

If you are already root, or the server has no `sudo`, end it with `| bash`.

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

## Fix and tune

The audit above only reads. `linux-host-fix.sh` is a separate file that can also change things:

```bash
curl -fsSL https://raw.githubusercontent.com/ashahmohammadi/linux-host-audit/main/linux-host-fix.sh | sudo bash -s -- --list
```

Save it first for the menus, because they need the terminal:

```bash
curl -fsSLO https://raw.githubusercontent.com/ashahmohammadi/linux-host-audit/main/linux-host-fix.sh && sudo bash linux-host-fix.sh
```

Every fix shows the exact cause, the plan and the risk, and asks first. It backs up what it changes,
tests the result, and rolls back if the problem stays or anything else stopped running. Changes that
could lock you out undo themselves unless you confirm from a new session. `--undo RUN` reverses any fix.
A fix that cannot be undone always needs the word yes typed by a person, or `--yes=high`. Panel
licenses are never read or checked.

It never reboots, never deletes sites, uploads or databases, never reruns one-shot jobs, never starts a
service that is switched off, and never edits an app config by guessing. Failing disks, signs of a
break-in and major upgrades get exact steps instead of an automatic change.

`--tune` shows how full every limit is and what real load asks for. `--tune-apply N` applies one piece
of advice. A service running for less than a day gets numbers, but no advice.

## What it covers

Overview, problems with fixes, applications (found by port, service and process, so unknown apps
appear too), ports and firewall, Docker, Podman, LXD, Incus, Proxmox, libvirt, Kubernetes (k8s, k3s,
k0s, RKE2, MicroK8s, OpenShift), websites, domains and SSL, databases and caches, security, logs,
application errors, scheduled jobs, backups, a live monitor, and a guided tour.

`--panel` is full troubleshooting for cPanel & WHM, Plesk and DirectAdmin: the version and how long
its vendor supports it, the update state, services, panel logs grouped and explained, sites on each PHP
version on cPanel, and the vendor's own commands for that panel. Tuning and fix steps also follow each
panel, because a panel rewrites the files it generates. So on a panel server this tool shows the right
place to change a setting and leaves those files alone. [SOURCES.md](SOURCES.md) lists the vendor page
behind each command, and says which were run for real and which only come from the documentation.

`--errors` reads a bounded tail of the error log of each running application: nginx, Apache, LiteSpeed,
PHP-FPM, MySQL, MariaDB, PostgreSQL, Redis, Valkey, MongoDB, Elasticsearch, OpenSearch, HAProxy, Varnish,
Tomcat, RabbitMQ, Kafka, ClickHouse, Cassandra, Squid, Exim, Postfix, Dovecot, PowerDNS, BIND, cPanel,
and the logs of each container. It groups repeated errors, counts them, and turns common ones into a
plain cause and a next step. Log lines can hold private data, so they appear in this view only, never
in `--report` or `--json`. Passwords and tokens are masked, as far as a pattern can tell.

Tuning has its own rules for MySQL, MariaDB, PostgreSQL, Redis, Valkey, Memcached, MongoDB,
Elasticsearch, OpenSearch, Nginx, Apache, LiteSpeed, HAProxy, Varnish, PHP-FPM, Tomcat, RabbitMQ,
ClickHouse, Squid, Caddy, Gunicorn, uWSGI, containers, Kubernetes and the Linux kernel. Kafka, Cassandra,
InfluxDB, MinIO, Traefik, Keepalived, Ceph, GlusterFS, Node.js and every JVM get the real numbers they
expose without a password, and a plain note where a limit cannot be read. Any other program with an
open port still gets its open file, thread and memory numbers.

Advice needs evidence. A service running for less than a day gets numbers only, and so does a limit
that nothing has come near.

`--help` lists every view. `--check` prints one status line and exits 0, 1 or 2 for cron or monitoring.

## For scripts and tools

`--json` prints the server facts (OS, version, package manager, init system) and every finding with
a stable `id`, its `target`, and its severity. Ids such as `disk-full` or `service-failed` are a
contract: other tools can act on them without reading the English text, so never rename one.

## Limits

- Bash is required, so Alpine needs `apk add bash`.
- Without root, some sections are partial, and the report says so.
- Pending updates are not checked on dnf and yum, because those tools write to their logs.
- Database details need passwordless local access. It never asks for a password.
- `--errors` hides values next to words such as `password`, but a secret with no such word can still
  print, so read that view before you share it.
- It only talks to services on this machine. For MongoDB it runs `mongosh` with `DO_NOT_TRACK=1`, but
  that this stops all of its telemetry is not proven, so block its outbound traffic if that matters.
- Reading a local metrics page can show up in that service's own access log.
- `kubectl` keeps its own small cache in `~/.kube`, which is the one write this tool can cause.
- Some tools are left out on purpose, because they write or log something: `rabbitmqctl`, `nodetool`,
  `gluster` and `ceph`. Those services show what their own metrics page or state files say.
- `ss` is used only where its kernel modules are loaded already. Otherwise the kernel would load them,
  so listeners and connections come from `/proc`.
- PostgreSQL details need root and `setpriv`. Password-protected services show less.
- A clean report means these checks found nothing. It does not prove a server is secure.

## Tests

`bash tests/run.sh` runs simulated servers with fake `docker`, `kubectl`, `ss` and other tools.
`tests/fix-real.sh` breaks a throwaway machine on purpose and fixes it. Never run it on a real server.
CI runs the second one, old and new distros, and real databases, web servers and queues across versions.
`tests/all-distros.sh` runs every view on about 70 releases. `tests/fix-distros.sh` runs the real
break-and-fix tests inside booted AlmaLinux and Ubuntu containers, so the host stays untouched.
`tests/parse-real.sh` checks the parsers on each distro's own awk, because mawk fails quietly.
Run `tests/run.sh` yourself before a release, because it is not in CI.
