# Where each command comes from

Commands, file paths and support dates in this tool follow the vendors' own documentation. This
list was checked on 5 November 2026. Vendors change their pages, so check a page again before you
rely on an old entry.

"Tested" says how each entry was proven: **real** means CI ran it against the real product,
**docs** means it was read in the vendor's documentation but not run.

## Hosting panels

| Panel | What the tool uses | Tested | Source |
|---|---|---|---|
| cPanel | Version numbers, tiers, end of life | docs, read on a live server | [Product versions](https://docs.cpanel.net/knowledge-base/cpanel-product/product-versions-and-the-release-process/) |
| cPanel | Log paths | docs, read on a live server | [The cPanel log files](https://docs.cpanel.net/knowledge-base/cpanel-product/the-cpanel-log-files/) |
| cPanel | `restartsrv_*` first, `systemctl` second | docs | [How to restart services](https://docs.cpanel.net/knowledge-base/general-systems-administration/how-to-restart-services/) |
| cPanel | `autossl_check --user`, `--all` | docs | [autossl_check](https://docs.cpanel.net/whm/scripts/the-autossl_check-script/) |
| cPanel | `servers_queue`, `queueprocd` | docs | [servers_queue](https://docs.cpanel.net/whm/scripts/the-servers-queue-script/) |
| cPanel | PHP-FPM files, `pm_max_children`, `php_fpm_config --rebuild` | docs, paths read on a live server | [Configuration values](https://docs.cpanel.net/knowledge-base/php-fpm/configuration-values-of-php-fpm/), [Domain pools](https://docs.cpanel.net/knowledge-base/php-fpm/php-fpm-domain-pools/), [File layout](https://docs.cpanel.net/knowledge-base/php-fpm/php-fpm-code-and-filesystem-layout-for-easyapache-4/) |
| cPanel | Apache limits in Global Configuration, `ea4.conf` | docs | [Global Configuration](https://docs.cpanel.net/whm/service-configuration/global-configuration/) |
| cPanel | `ea-nginx/settings.json`, `worker_processes` | docs | [Customize NGINX](https://docs.cpanel.net/knowledge-base/nginx/customize-reverse-proxy-nginx-configurations/) |
| cPanel | `cpanel-csf`, firewalld must go first | docs | [How to install CSF](https://docs.cpanel.net/knowledge-base/third-party/how-to-install-csf/) |
| cPanel | `configure_firewall_for_cpanel` clears rules | docs | [Firewall for cPanel services](https://docs.cpanel.net/knowledge-base/general-systems-administration/how-to-configure-your-firewall-for-cpanel-services/) |
| cPanel | MySQL and MariaDB versions per OS | docs | [Supported versions](https://docs.cpanel.net/knowledge-base/general-systems-administration/supported-mysql-mariadb-versions/) |
| Plesk | `plesk version`, `db`, `log`, `repair`, `listupgrade`, `checkupgrade`, `installer` | real | [Plesk utility](https://docs.plesk.com/en-US/obsidian/cli-linux/plesk-utility.75661/) |
| Plesk | `repair all -n`, `-y`, run off-peak | real | [Repair utility](https://docs.plesk.com/en-US/obsidian/administrator-guide/plesk-administration/plesk-repair-utility/plesk-repair-utility-all.74650/) |
| Plesk | Log and service names | real | [Services, logs and config files](https://support.plesk.com/hc/en-us/articles/12377744787991-Plesk-for-Linux-services-logs-and-configuration-files) |
| Plesk | `php_handler --list` | real | [php_handler](https://docs.plesk.com/en-US/17.0/cli-linux/using-command-line-utilities/php_handler-custom-php-handlers.72490/) |
| Plesk | `MaxRequestWorkers` files and formula | docs | [MaxRequestWorkers](https://support.plesk.com/hc/en-us/articles/36408797961879-How-to-calculate-and-adjust-the-MaxRequestWorkers-limit-on-the-server-with-Plesk) |
| Plesk | PHP-FPM per domain, in PHP Settings | docs | [Customize PHP settings](https://www.plesk.com/kb/support/how-to-customize-php-settings-in-plesk/) |
| Plesk | Support rules | docs | [Lifecycle policy](https://plesk.com/lifecycle-policy) |
| DirectAdmin | `da` commands, `directadmin v` | docs | [The directadmin binary](https://docs.directadmin.com/directadmin/general-usage/directadmin-binary.html) |
| DirectAdmin | Paths, logs, `conf/my.cnf` | docs | [Directories and locations](https://docs.directadmin.com/directadmin/general-usage/directories-and-locations.html) |
| DirectAdmin | Debug mode, port 2222, login problems | docs | [Troubleshooting the service](https://docs.directadmin.com/directadmin/general-usage/troubleshooting-da-service.html) |
| DirectAdmin | `task.queue`, `dataskq` | docs | [Task queue processor](https://docs.directadmin.com/directadmin/general-usage/task-queue-processor.html) |
| DirectAdmin | `custombuild/custom`, `rewrite_confs` | docs | [Customize everything](https://docs.directadmin.com/custombuild/customize-everything.html) |
| DirectAdmin | `php_fpm_max_children_default`, `MAX_CHILDREN` | docs | [PHP-FPM](https://docs.directadmin.com/webservices/php/php-fpm.html) |
| DirectAdmin | Upgrading MySQL and MariaDB | docs | [MariaDB and MySQL](https://docs.directadmin.com/other-hosting-services/mariadb-mysql/index.html) |
| DirectAdmin | Certificate logs | docs | [Let's Encrypt errors](https://docs.directadmin.com/webservices/ssl/troubleshooting-letsencrypt.html) |
| DirectAdmin | Exim commands | docs | [Exim queue](https://docs.directadmin.com/other-hosting-services/exim/maintaining-email-queue.html) |

## Applications

| App | Rule in the tool | Tested | Source |
|---|---|---|---|
| Apache on Debian | Only `apache2ctl` reads the config, not `apache2` | real | [README.Debian](https://sources.debian.org/src/apache2/2.4.66-5/debian/apache2.README.Debian) |
| MySQL | `innodb_redo_log_capacity` is set live | real, 8.0, 8.4 | [Redo log](https://dev.mysql.com/doc/refman/8.4/en/innodb-redo-log.html) |
| MariaDB | `innodb_log_file_size` is live from 10.9 | real, 10.5 to 11.8 | [System variable](https://mariadb.com/docs/server/ref/mdb/system-variables/innodb_log_file_size) |
| MariaDB, MySQL | Live buffer pool resize | real, 5.7 to 11.8 | Same pages |
| k3s | `certificate check`, `rotate`, renewal within 120 days | docs | [k3s certificate](https://docs.k3s.io/cli/certificate) |
| RKE2 | `certificate check`, `rotate` | docs | [RKE2 certificates](https://docs.rke2.io/security/certificates) |
| dnf5 | `updateinfo` is an alias of `advisory` | docs | [dnf5 advisory](https://dnf5.readthedocs.io/en/latest/commands/advisory.8.html) |

## Support dates

Support dates for operating systems, PHP, MariaDB, MySQL, PostgreSQL, Node.js, MongoDB and Redis
were compared with [endoflife.date](https://endoflife.date), which links each date to the vendor's
own page. cPanel dates come from its product versions page above.

## Known gaps

- cPanel and DirectAdmin need a paid license, so CI cannot run them. Their commands are read from the
  documentation, and the cPanel paths were also read on one live AlmaLinux 8 server, version 138.
- The `kubeadm alpha certs` form for Kubernetes before 1.20 comes from memory of the old manual.
- Elastic's documentation shows `$ES_HOME/config/certs/http_ca.crt`. The `/etc/elasticsearch/certs/`
  path for a package install comes from third-party guides.
