# Containerizing a service - `containers/ccdc-container.sh`

Containers for the scored Linux services, built **on the box they replace**, from **that box's own repositories and
installed packages**, running with the box's **own network, code, config, data and users**. Only do it when there's a
reason (an inject asks for it, or a vulnerable service gets isolated from the rest of the OS) - and practise it in the
lab first. The switch takes seconds and rolls itself back if anything fails.

```bash
sudo bash containers/ccdc-container.sh list              # which services this box can containerize
sudo bash containers/ccdc-container.sh plan ecom-web     # packages, image, mounts, run command - changes nothing
sudo bash containers/ccdc-container.sh build ecom-web    # build the image here (5-10 min, needs the internet)
sudo bash containers/ccdc-container.sh switch ecom-web   # host service -> container (tested, auto-rollback)
sudo bash containers/ccdc-container.sh rollback ecom-web # container -> host service
sudo bash containers/ccdc-container.sh status
```

| Service | Box | Runs in the container | Stays on the host (mounted at the same path) |
|---|---|---|---|
| `ecom-web` | Rocky E-com | Apache `httpd` + PHP (`php-fpm`) | `/var/www`, `/etc/httpd`, PHP config, certificates, logs, sessions, the MariaDB socket |
| `ecom-db` | Rocky E-com | MariaDB / MySQL (same major.minor - checked before the switch) | `/var/lib/mysql` (the data), `my.cnf`, logs |
| `mail` | Ubuntu Email | Postfix + Dovecot (+ rsyslog for `mail.log`) | `/etc/postfix`, `/etc/dovecot`, the queue, every mailbox, `/etc/passwd`/`shadow`/`group`, PAM, the SSSD socket (AD users), certificates |
| `webmail` | Ubuntu Email | Apache + PHP | Roundcube's code (`/usr/share/roundcube`), config, database, `/etc/apache2`, `/etc/php`, logs |
| `splunk` | Debian Splunk | the OS around Splunk | the whole `/opt/splunk` (binaries, config, indexes), `/var/log` read-only |
| `ftp` | any box with vsftpd | vsftpd | its config, users, files |

**Not containerized:** AD/DNS and MSSQL (Windows Server - Active Directory can't run in a container, and moving SQL
Server into a Linux container would change the platform, which the rules forbid), and the workstations (rule: they
may not be re-tasked - the script refuses `CCDC_ROLE=workstation`).

## How it keeps each rule
| Rule (2026 pack) | How |
|---|---|
| Same platform (Systems 8, Play 8) | Built and run on the same VM; `switch` stops the host service and starts the container right there |
| Same "public" IP and DNS naming (Systems 6, 7, 8) | `--network host`: the box's own IP, ports and hostname - the Palo Alto NAT, DNS records and the scorer see no difference; host firewall rules (`fw.sh`) still apply |
| Same content, data, functionality (Play 8) | Nothing is copied: code, config and data are the host's files, mounted at the same paths. `switch` compares the scored page / banners / ports before and after and rolls back on any difference |
| Same user set (Play 8, 11) | The host's `/etc/passwd`, `shadow`, `group`, PAM and SSSD are mounted - same users, same IDs, same passwords |
| Same software | The image uses the same distribution and release as the box, the box's own repo files and GPG keys, the same package names (and dnf module streams, e.g. `php:8.1`) - versions match up to the latest patch from those repos |
| Free / open source, public sources (Play 10, Internet 4) | Podman / Docker CE from the distro, official base images from Docker Hub (`rockylinux/rockylinux`, `ubuntu`, `debian`) |

## What `switch` does
1. Refuses if the service can't run here, there's no image, or it's a workstation.
2. **Tests the host service now** (scored page over HTTP/HTTPS, mail banners, ports) and records what passes.
   `ecom-db`: also refuses if the image's server version differs from the host's (it would upgrade the data files).
3. Wants a backup from the last hour (offers `linux/backup.sh`).
4. Stops the host units, starts the container (`--network host`, `--restart`, journald logs, the mounts).
5. Waits for every recorded check to pass again (same page content, same banners). **Any failure → stops the
   container, starts the host service again, prints the container log.**
6. Success → masks the host units (they can't start by accident and fight over the ports or the database) and makes
   the container start at boot (Podman: `podman-restart.service`; Docker: the `docker` service).

`rollback` removes the container (the image stays), unmasks and starts the host units again.

## Things to know
- **SELinux (Rocky):** containers run with `--security-opt label=disable`, so the mounted files keep their normal
  labels and the host service can take over again at any time. (Relabelling mounts with `:z` / `:Z` would lock the
  host's `httpd` / `mysqld` out of their own files and break rollback - if someone did that: `restorecon -Rv /var/www /var/lib/mysql`.)
- **Mail users:** `/etc/passwd`/`shadow` are mounted as files - after changing a **local** password on the host, run
  `docker restart ccdc-mail` (or `podman restart`) so the container sees the new file. AD users (SSSD) need nothing.
  Run `newaliases` / `postmap` inside: `docker exec ccdc-mail newaliases`.
- **Config changes** are still made on the host files (they're mounted); then restart the container
  (`docker restart ccdc-<service>`) instead of `systemctl reload`. Check config first inside it:
  `docker exec ccdc-ecom-web httpd -t`, `docker exec ccdc-mail postfix check`.
- **Our tools keep working:** webguard, fim, backups (`backup.sh` dumps MySQL through the same socket), the Splunk
  forwarder and `fw.sh` (host networking = the INPUT rules apply; it detects Docker/Podman and leaves their chains alone).
  `secure.sh web` / `mail` look for host services - run them **before** switching (the config they write is mounted, so it carries over).
- **Security of the container itself:** no `--privileged`, no Docker socket mounted, `no-new-privileges` where the
  service allows it (not for mail: Postfix's `postdrop` needs its setgid bit). Nobody in the `docker` group
  (`getent group docker` - it's root-equivalent; `linux/privesc.sh` flags it). The Docker API must not listen on the
  network (`ss -ltnp | grep -E ':237[56]'` → nothing). `docker image ls` / `podman images`: only `localhost/ccdc-*` and the base images.
- **Building needs the internet** (packages from the box's repos) - outbound DNS/HTTP/HTTPS, which the Palo Alto policy
  and `fw.sh` allow. Build early; the image can sit unused until it's needed.
- **Logs:** `docker logs -f ccdc-<service>` / `journalctl CONTAINER_NAME=ccdc-<service>`; the services' own log files
  stay in `/var/log/...` on the host.

## Verify before telling anyone it's done
- [ ] `switch` printed "every check passed"
- [ ] **From Kali** (the scorer's path): the scored page / banners / ports, as in `kali/HARDENING.md` section 4
- [ ] Quotient green for that service for 10+ minutes
- [ ] Data and users: same products / mailboxes / messages; a scored user logs in with the current password
- [ ] It survives a reboot (plan it with the captain): the container comes back, the host units stay masked
- [ ] Inject answer: what was containerized, the image (`docker image inspect localhost/ccdc-<service>:current`),
      the mounts (`plan` output), how to roll back (`rollback`)

## Testing status
Tested here: the package selection, base-image choice and run command for every service against simulated Ubuntu
22.04 / Debian 12 / Rocky 9 package lists, and the before/after checks against test services (a changed page is
caught). **Not yet built or run with a real engine** - build and switch each service on lab copies of the boxes first.
