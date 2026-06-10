# VPS hygiene runbook

The public VPS exposes only three services to the internet: `sshd` (port 22, for you and the reverse-tunnel user), Caddy (443), and Postfix (25). This runbook locks down each to a level a production auditor would accept for a one-person project.

> **Every step in this runbook runs on the VPS** (the public Rocky Linux box at `mailtest.justfortesting.xyz`). The `[VPS]` prefix on each heading is there for consistency with the other runbooks — if a sub-step needs to be run from somewhere else (e.g. a sanity-check from a second machine), it's called out inline.

> **Important.** Keep a second SSH session open while you apply any `sshd_config` change, and run `sudo sshd -t` before reloading. Lock-out recovery on a VPS is slow and painful.

---

## 1) [VPS] SSH: key-only, no root, keepalives

Edit `/etc/ssh/sshd_config` (or drop a file under `/etc/ssh/sshd_config.d/`) and set:

```sshd_config
# Kill passwords everywhere. Keys or nothing.
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no

# No direct root login even with a key. Use sudo from your personal user.
PermitRootLogin no

# Reverse tunnels (the whole reason this VPS exists) bind to loopback only
# by default. Keep it that way so nobody can re-expose a forwarded port.
GatewayPorts no

# Kick dead clients and stale reverse-tunnels within ~2 minutes. This is
# what frees port 18080 after the home machine reboots.
ClientAliveInterval 60
ClientAliveCountMax 2
```

Apply:

```bash
sudo sshd -t && sudo systemctl reload sshd
```

Confirm passwords really are off — run this **from your home machine** (or any other host), not from the VPS itself:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no you@vps
# Expected: "Permission denied (publickey)."
```

---

## 2) [VPS] fail2ban (optional, cheap)

Even with key-only auth, brute-force attempts eat CPU and fill your logs. `fail2ban` bans offending IPs at the firewall.

```bash
# Rocky / RHEL
sudo dnf install -y fail2ban
# Debian / Ubuntu
# sudo apt install -y fail2ban
```

Create `/etc/fail2ban/jail.d/sshd.local`:

```ini
[sshd]
enabled  = true
port     = ssh
backend  = systemd
maxretry = 4
findtime = 10m
bantime  = 1h
```

Enable and verify:

```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

After a day or two:

```bash
sudo fail2ban-client status sshd | grep 'Banned IP list'
```

You'll usually see a handful of Chinese/Russian/DigitalOcean IPs camping on port 22. That's normal internet background noise.

---

## 3) [VPS] Postfix: confirm no open relay, confirm rate limits

Already covered in the main project's abuse-mitigation write-up, but re-run this after any Postfix edit:

```bash
postconf -n | grep -E 'smtpd_relay_restrictions|smtpd_recipient_restrictions|mynetworks|relay_domains'
```

- `smtpd_relay_restrictions` **must** include `reject_unauth_destination` (or `reject_non_fqdn_recipient`).
- `relay_domains` must be empty or list only `$mydestination`. Entries like `*` or a domain you don't own = open relay = abused within hours.

Confirm the rate limits from the main runbook are still in place:

```bash
postconf message_size_limit \
         smtpd_client_connection_rate_limit \
         smtpd_client_message_rate_limit \
         smtpd_client_recipient_rate_limit \
         smtpd_client_event_limit_exceptions \
         anvil_rate_time_unit
```

Expected (current defaults in this project):

```
message_size_limit = 2097152
smtpd_client_connection_rate_limit = 10
smtpd_client_message_rate_limit = 5
smtpd_client_recipient_rate_limit = 10
smtpd_client_event_limit_exceptions = 127.0.0.0/8,[::1]/128,$mynetworks
anvil_rate_time_unit = 60s
```

---

## 4) [VPS] Firewall: only the ports you actually serve

```bash
sudo nft list ruleset
```

Expected inbound accepts on `inet filter input`:

| Port | Why |
|--|--|
| 22/tcp | SSH (you + tunnel user) |
| 25/tcp | Postfix inbound MX |
| 80/tcp | Caddy HTTP-01 challenge (TLS cert renewal) |
| 443/tcp | Caddy HTTPS |

Everything else should fall through to `policy drop`.

If you see a `51820/udp` accept left over from an earlier WireGuard experiment and you're not using WireGuard now, drop it:

```bash
sudo nft delete rule inet filter input handle <handle>   # get handle from `nft -a list ruleset`
sudo nft list ruleset | sudo tee /etc/sysconfig/nftables.conf >/dev/null
```

---

## 5) [VPS] Unattended security upgrades

Rocky / RHEL:

```bash
sudo dnf install -y dnf-automatic
sudo systemctl enable --now dnf-automatic.timer
```

Then edit `/etc/dnf/automatic.conf` and set:

```ini
[commands]
upgrade_type = security
apply_updates = yes
```

(Rocky's default is `apply_updates = no`, which merely downloads them.)

Debian / Ubuntu equivalent:

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## 6) [VPS] Periodic review checklist

Once a quarter, five minutes:

```bash
# Who has shell access?
awk -F: '$3>=1000 && $7!~/nologin|false/ {print $1}' /etc/passwd

# Who can sudo?
sudo getent group wheel sudo

# Any surprise listening sockets?
sudo ss -lntp

# Any surprise running services?
systemctl list-units --type=service --state=running --no-pager

# Recent ban activity?
sudo fail2ban-client status sshd

# Certs about to expire? (Caddy handles renewal, but sanity-check.)
sudo journalctl -u caddy --since "7 days ago" | grep -iE 'certificate|renew|error'
```
