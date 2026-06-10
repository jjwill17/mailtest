# Persistent SSH reverse tunnel (home → VPS)

The public site at `demo.mailtest.justfortesting.xyz` is useless the moment this tunnel dies. This runbook makes the tunnel survive reboots, flaky Wi-Fi, and VPS restarts by running `autossh` under `systemd`.

```
                       VPS :443 (Caddy) ──▶ VPS 127.0.0.1:18080
                                                   ▲
                                                   │  SSH reverse-forward
                                                   │  (autossh, restricted key)
                                                   │
                                    Home :8080 (FastAPI in Docker)
```

> **Which machine does what?** Every step below is prefixed with **`[VPS]`** or **`[home]`** to make this unambiguous. `[VPS]` = the public Rocky Linux box at `mailtest.justfortesting.xyz`. `[home]` = the machine behind your NAT that runs `docker compose`.

---

## 1) [VPS] Dedicated tunnel user

Running the tunnel as `root` or your personal login is a footgun. A locked-down user with a restricted key is the right primitive.

On the VPS:

```bash
sudo useradd --shell /usr/sbin/nologin --create-home --home /home/tunnel tunnel
sudo install -d -m 700 -o tunnel -g tunnel /home/tunnel/.ssh
sudo install -m 600 -o tunnel -g tunnel /dev/null /home/tunnel/.ssh/authorized_keys
```

`nologin` means nobody can land a shell as this user even if the key leaks — they can only open the tunnel.

## 2) [home] Dedicated SSH key

On the home machine (not your everyday personal key):

```bash
ssh-keygen -t ed25519 -N "" -C "mailtest-tunnel@home" \
  -f ~/.ssh/mailtest_tunnel_ed25519
cat ~/.ssh/mailtest_tunnel_ed25519.pub
```

## 3) [VPS] Install the key with tunnel-only restrictions

On the VPS, paste the `.pub` contents into `/home/tunnel/.ssh/authorized_keys` prefixed with restrictions that allow **only** the one reverse-forward we need:

```
no-agent-forwarding,no-user-rc,no-x11-forwarding,no-pty,permitlisten="localhost:18080" ssh-ed25519 AAAA... mailtest-tunnel@home
```

- `no-pty,no-X11-forwarding,no-agent-forwarding,no-user-rc` together match what `restrict` would give us (no shell, no pty, no agents, no `.ssh/rc`).
- `permitlisten="localhost:18080"` re-allows exactly one reverse-forward, bound to the VPS loopback.

Why not just `restrict,permitlisten="localhost:18080"`? The `authorized_keys(5)` man page says `permitlisten` is supposed to override the implicit `no-port-forwarding` added by `restrict`, but on Rocky/RHEL 9's OpenSSH 8.7p1 build that override doesn't take effect and the server reports *"Server has disabled port forwarding."* Spelling the restrictions out explicitly avoids the footgun. Extra defense in depth: the `tunnel` user already has `/usr/sbin/nologin` from step 1, so even if all of this failed open, there's still no shell.

## 4) [home] Smoke-test the tunnel by hand

Before systemd-ifying it, prove it works. From the **home** machine:

```bash
ssh -i ~/.ssh/mailtest_tunnel_ed25519 -N \
  -R 18080:localhost:8080 \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes \
  tunnel@mailtest.justfortesting.xyz
```

Leave that running. In a second terminal on the **VPS**, confirm the port is bound on loopback and the app responds:

```bash
ss -lntp | grep 18080
curl -s http://127.0.0.1:18080/health    # -> {"status":"ok"}
```

Back on **home**, Ctrl-C the foreground SSH once the health check succeeds.

## 5) [home] Install the systemd unit

Two templates in this directory: [`mailtest-tunnel.service`](./mailtest-tunnel.service) and [`mailtest-tunnel.env.example`](./mailtest-tunnel.env.example).

```bash
# Install the env file — secrets inside, so root-only.
sudo install -m 600 -o root -g root \
  ops/home-tunnel/mailtest-tunnel.env.example \
  /etc/mailtest-tunnel.env
sudoedit /etc/mailtest-tunnel.env    # fill in SSH_TARGET, SSH_KEY, etc.

# Install the unit. Adjust User= if your login isn't `justin`.
sudo install -m 644 \
  ops/home-tunnel/mailtest-tunnel.service \
  /etc/systemd/system/mailtest-tunnel.service
sudoedit /etc/systemd/system/mailtest-tunnel.service

sudo systemctl daemon-reload
sudo systemctl enable --now mailtest-tunnel
```

## 6) [home + VPS] Verify

On **home**:

```bash
systemctl status mailtest-tunnel --no-pager
journalctl -u mailtest-tunnel -f
```

On the **VPS**:

```bash
ss -lntp | grep 18080
curl -sI https://demo.mailtest.justfortesting.xyz/health
```

## 7) [home] Kill-test

Reboot the home machine. Within ~60 seconds the tunnel should self-heal:

```bash
journalctl -u mailtest-tunnel --since "5 minutes ago"
```

---

## Troubleshooting

| Symptom | Fix |
|--|--|
| `bind: Address already in use` on the VPS | A stale `sshd` on the VPS is still holding `18080`. The VPS's own `ClientAliveInterval` will reap it within ~2 min; or force with `sudo pkill -f 'sshd.*tunnel'` on the VPS. |
| Tunnel flaps every few minutes | Increase `ServerAliveInterval` or check the VPS's `ClientAliveInterval` in `sshd_config` — a mismatch causes unnecessary kills. |
| Tunnel up but Caddy shows `502` | Confirm `tunnel` user's `authorized_keys` has `permitlisten="18080"` and the API container is listening on home `127.0.0.1:8080` (`docker compose ps api`). |
| `autossh: command not found` | `sudo apt install autossh` (Debian/Ubuntu) or `sudo dnf install autossh` (Rocky/Fedora). |
| Unit starts then exits | `journalctl -u mailtest-tunnel -n 50` — most common cause is the wrong key path in `/etc/mailtest-tunnel.env`. |
