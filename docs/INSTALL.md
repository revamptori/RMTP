# Installation

## From source

```bash
git clone <repo> RMTP
cd RMTP
cargo build --release
sudo cp target/release/rustsmtp /usr/local/bin/
```

## Systemd

```bash
sudo mkdir -p /opt/rmtp/data /opt/rmtp/certs
sudo cp target/release/rustsmtp /opt/rmtp/
sudo cp rmtp.toml.example /opt/rmtp/rmtp.toml
sudo cp contrib/rmtp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rmtp
```

Edit `/opt/rmtp/rmtp.toml` for your hostname, TLS certificate/key, and
credentials. TLS certificates must be readable by the `rmtp` user.

## Running from terminal

```bash
rustsmtp init            # create rmtp.toml
rustsmtp config validate # check it
rustsmtp start           # run in foreground (Ctrl-C to stop)
```

`rustsmtp start` runs in the foreground; use systemd (above) or a process
supervisor (supervisord, runit) for background operation. RMTP is terminal-only
and has no daemonize/double-fork by design.

## Unprivileged port

Ports below 1024 (e.g. 25) require root or `CAP_NET_BIND_SERVICE`. Either run
on a high port (587) or grant the capability:

```bash
sudo setcap cap_net_bind_service=+eip /usr/local/bin/rustsmtp
```

## Security checklist

- [ ] TLS certificate + private key configured when auth is enabled
- [ ] Passwords not committed to version control (use env vars)
- [ ] Queue directory permissions restrict access to the service user
- [ ] `max_message_size` set to prevent resource exhaustion
- [ ] `max_connections` tuned to available RAM
