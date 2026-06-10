# Production MX: VPS inbound → WireGuard → home `email-bridge`

This runbook wires **public SMTP (port 25)** on your VPS (`209.141.48.115`, Rocky Linux 9) to your **home Docker stack** over **WireGuard**, delivering mail to `email-bridge` on **TCP 10025** (same as [docker-compose.yml](../../docker-compose.yml)).

**Flow**

```text
Internet → VPS Postfix :25 → WG tunnel → home :10025 → email-bridge → api /ingest
```

**SMTP MAIL FROM (envelope sender)**

SPF must use the address from the inbound `MAIL FROM` command, not the friendly `From:` header.
That value is available on the VPS as soon as Postfix accepts the message. Hand it to home in one of two ways:

| VPS delivery | How MAIL FROM reaches home |
|--------------|----------------------------|
| **Recommended:** `transport` → `smtp:[home-wg-ip]:10025` | Postfix opens a second SMTP session to `email-bridge` and sends the **same** `MAIL FROM`. The bridge reads `envelope.mail_from` and posts it to `/ingest` as `smtp_envelope_from` + `X-Mailtest-Envelope-From`. |
| **Alternate:** `mailtest-pipe` → HTTP `127.0.0.1:18080/ingest` | Postfix sets `$sender` in the pipe process environment; `postfix_pipe_ingest.py` sends `smtp_envelope_from` in the JSON body. |

Do **not** rely on `Return-Path:` being present in the MIME at capture time — Gmail adds that at delivery; your relay/pipe path often does not include it unless you record MAIL FROM explicitly (as above).

**Prerequisites (you already did DNS)**

- `A` `mailtest.justfortesting.xyz` → `209.141.48.115`
- `MX` for `mailtest.justfortesting.xyz` points at that hostname
- VPS hostname set to `mailtest.justfortesting.xyz`

**Security**

- Do **not** paste private keys or root passwords into chat.
- Restrict home TCP `10025` to the **VPS WireGuard IP** only (firewall).

---

## 1) WireGuard: pick a tunnel subnet

Use a private /24 that does not overlap your LAN or Docker networks, e.g. **`10.200.0.0/24`**:

| Role | WireGuard IP |
|------|----------------|
| VPS | `10.200.0.1/24` |
| Home | `10.200.0.2/24` |

Replace in configs below if you choose different addresses.

---

## 2) Generate keys (on either machine)

```bash
umask 077
wg genkey | tee wg-private.key | wg pubkey > wg-public.key
cat wg-public.key
```

Keep `wg-private.key` private. You need **two** keypairs (VPS + home), or generate one per host.

---

## 3) Configure WireGuard on the **VPS** (Rocky 9)

Install:

```bash
sudo dnf install -y wireguard-tools
```

Create `/etc/wireguard/wg0.conf` from [vps-wg0.conf.example](./wireguard/vps-wg0.conf.example):

- Set `PrivateKey` to the **VPS** private key.
- Set `[Peer] PublicKey` to the **home** public key.
- Set `AllowedIPs = 10.200.0.2/32` (home’s WG address).

Enable:

```bash
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

Firewall (firewalld) — allow WireGuard UDP (default **51820**):

```bash
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --permanent --add-service=smtp
sudo firewall-cmd --reload
```

---

## 4) Configure WireGuard on **home** (Linux host that runs Docker)

Install WireGuard the usual way for your distro, then create `wg0.conf` from [home-wg0.conf.example](./wireguard/home-wg0.conf.example):

- `PrivateKey` = home private key
- `[Peer] PublicKey` = VPS public key
- `Endpoint = 209.141.48.115:51820`
- `AllowedIPs` can be `10.200.0.1/32` (VPS tunnel IP only) for a minimal route.

Bring interface up, then verify from **home**:

```bash
ping -c 3 10.200.0.1
```

From **VPS**:

```bash
ping -c 3 10.200.0.2
```

If ping fails, check firewalld on VPS for `51820/udp`, and that home NAT allows outbound UDP to the VPS.

---

## 5) Lock down **home** port 10025

`email-bridge` publishes `10025:10025` on the host. Allow **only** the VPS WireGuard IP:

**nftables example** (run on home; adjust interface names):

```bash
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority 0 ; policy drop; }'
sudo nft add rule inet filter input iif "lo" accept
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter input ip saddr 10.200.0.1 tcp dport 10025 accept
# add rules for ssh, etc., before the final drop — or use firewalld/ufw with equivalent rich rules
```

**firewalld example**:

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.200.0.1/32" port port="10025" protocol="tcp" accept'
sudo firewall-cmd --reload
```

Ensure Docker is listening on `10025` when the stack is up (`docker compose ps`).

Test from **VPS**:

```bash
nc -vz 10.200.0.2 10025
```

---

## 6) Postfix on **VPS** (relay to home)

Install:

```bash
sudo dnf install -y postfix
```

Copy snippet files:

- Merge [vps/postfix-main.cf.snippet](./vps/postfix-main.cf.snippet) into `/etc/postfix/main.cf` (or `postconf -e` each line).
- Install [vps/transport.example](./vps/transport.example) as `/etc/postfix/transport` and set **`HOME_WG_IP=10.200.0.2`** (your home WireGuard IP).

Build maps and restart:

```bash
sudo postmap /etc/postfix/transport
sudo postfix check
sudo systemctl enable --now postfix
sudo postfix reload
```

Verify Postfix listens on 25:

```bash
sudo ss -lntp | grep ':25'
```

---

## 7) End-to-end test

From an external mailbox (Gmail, etc.), send to:

- `check@mailtest.justfortesting.xyz` — normal capture (default test inbox)
- `complaint@mailtest.justfortesting.xyz` — same capture plus a second row: a synthetic [RFC 5965](https://www.rfc-editor.org/rfc/rfc5965.html) abuse feedback (`multipart/report`) like Amazon SES’s complaint simulator
- `bounce@mailtest.justfortesting.xyz` — SMTP `550 5.1.1 User unknown` at RCPT time, like SES’s bounce simulator ([SES mailbox simulator](https://docs.aws.amazon.com/ses/latest/dg/send-an-email-from-console.html))

If you use the **Docker** relay with a per-address `relay/transport` map, ensure `complaint@` and `bounce@` are relayed to the bridge (same target as `check@`). See [`relay_transport_simulator.snippet`](../../relay_transport_simulator.snippet) at the repo root for lines to merge in.

Watch on **home**:

```bash
docker compose logs -f email-bridge api
```

Watch on **VPS**:

```bash
sudo journalctl -u postfix -f
```

Confirm a row appears in your UI (`/ui/tests`) and `GET /tests/{id}/analysis` shows deliverability.

---

## 8) TLS on SMTP (optional but recommended)

For inbound, many senders still deliver without TLS to port 25, but offering **STARTTLS** is good practice.

Typical approach on Rocky:

- Install certbot + nginx or use **standalone** HTTP challenge on `80`.
- Obtain cert for `mailtest.justfortesting.xyz`.
- Point Postfix at the cert/key (`smtpd_tls_cert_file`, `smtpd_tls_key_file`) and set `smtpd_tls_security_level = may`.

Details depend on whether you already run a web server on the VPS; add certbot steps when ready.

---

## Re-syncing the VPS pipe script

If you use the alternate `mailtest-pipe` path, the wrapper, master.cf line, and Python
script all live on the VPS outside the repo. They drift the moment
[`scripts/postfix_pipe_ingest.py`](../../scripts/postfix_pipe_ingest.py) or
[`scripts/postfix-pipe-mailtest.snippet.txt`](../../scripts/postfix-pipe-mailtest.snippet.txt)
changes. Re-sync with:

```bash
# From the home machine
scp scripts/postfix_pipe_ingest.py \
  root@mailtest.justfortesting.xyz:/usr/local/lib/mailtest/postfix_pipe_ingest.py

# On the VPS
sudo chmod 755 /usr/local/lib/mailtest/postfix_pipe_ingest.py
sudo chown root:root /usr/local/lib/mailtest/postfix_pipe_ingest.py
sudo rm -rf /usr/local/lib/mailtest/__pycache__   # bust stale .pyc bytecode
```

No `postfix reload` is needed — pipe(8) spawns a fresh `python3` per delivery.

If you edit the `mailtest-pipe` line in `/etc/postfix/master.cf` (e.g. to pass `SENDER`
through `/usr/bin/env`), then run:

```bash
sudo postfix check && sudo systemctl reload postfix
```

How to confirm the new script is live:

```bash
ls -l /usr/local/lib/mailtest/postfix_pipe_ingest.py   # mtime + size match the repo
```

Then send a fresh test email and query the home DB:

```bash
docker compose exec db psql -U mailtest -d mailtest -c "
  select id,
         deliverability->'facts'->'header_facts'->>'envelope_from_source' as env_from_src,
         deliverability->'facts'->'auth_details'->'spf'->>'envelope_from'  as spf_envelope
  from test_emails order by id desc limit 1;
"
```

`env_from_src` should be `smtp-envelope` and `spf_envelope` should be the real per-message
bounce address, not the friendly `From:` header.

---

## Troubleshooting

| Symptom | Check |
|--------|--------|
| No connection VPS→home:10025 | `wg show`, ping `10.200.0.x`, firewall on home |
| Postfix on VPS rejects RCPT | `relay_domains`, `transport_maps`, `postmap`, `postfix check` |
| Bridge rejects mail | [bridge/bridge.py](../../bridge/bridge.py) accepts `check@`, `complaint@`, and `bounce@` (see README §7); other local parts get `550 No such user` |
| Mail loops | Ensure VPS does **not** list home as MX in public DNS (MX should stay VPS) |
| Pipe-ingest captures `<>` even for real senders | Postfix `pipe(8)` is documented to export `SENDER`, but some builds (e.g. Rocky 9 / Postfix 3.x) don't. Pass it explicitly in `master.cf`: `argv=/usr/bin/env SENDER=${sender} /usr/local/bin/mailtest-pipe-ingest ${recipient}`. |

---

## Files in this directory

| File | Purpose |
|------|---------|
| [wireguard/vps-wg0.conf.example](./wireguard/vps-wg0.conf.example) | VPS WireGuard template |
| [wireguard/home-wg0.conf.example](./wireguard/home-wg0.conf.example) | Home WireGuard template |
| [vps/postfix-main.cf.snippet](./vps/postfix-main.cf.snippet) | Postfix `main.cf` additions |
| [vps/transport.example](./vps/transport.example) | Transport map → home `smtp:[IP]:10025` |
