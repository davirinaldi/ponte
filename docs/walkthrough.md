# Walkthrough: one machine, end to end

Everything M1 built, run locally: PostgreSQL, the server, two agents, enrollment, approval,
revocation, a server that goes away and comes back, a second server that is refused, and
the agent's footprint. It takes about half an hour, 15 minutes of it measuring.

The agent and the server speak protocol version 2 only (ADR-0012). An agent built before
it cannot connect: build it again from this tree. Its identity in `keys/walkthrough` still
works.

Commands are for bash (Git Bash on Windows works), run from the root of the repository.
Where PowerShell differs, its version follows. Log lines are shortened here: the real ones
start with a timestamp and carry more fields.

You need Rust (rustup installs the pinned version), Docker, and four terminals: **server**,
**agent**, **second agent** and **operator**.

## 1. The database

In the operator terminal:

```sh
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps        # wait for "healthy"
```

The server and operator terminals need the URL. Use `127.0.0.1`, not `localhost`: Docker
publishes the port on IPv4 only, and on Windows a refused attempt on `::1` costs two seconds
on every new connection.

```sh
export DATABASE_URL=postgres://ponte:ponte@127.0.0.1:5432/ponte
```

```powershell
$env:DATABASE_URL = "postgres://ponte:ponte@127.0.0.1:5432/ponte"
```

## 2. Build, migrate, a customer and a token

Release builds, the agent's the one measured at the end. Build it on its own: in one
build with the server, cargo unifies features and the agent gets code it does not ship
with (rustls's TLS 1.2, from sqlx).

```sh
cargo build --release -p ponte-server
cargo build --release -p ponte-agent
cargo run -q --release -p ponte-server -- migrate
cargo run -q --release -p ponte-server -- customer create "Demo Customer"
```

`migrate` prints nothing when it worked. `customer create` prints the new customer's id.
On a database that already has a customer of that name it answers `a customer with that
name already exists`: `customer list` shows the id of the one there. Keep the id:

```sh
CUSTOMER=<the id it printed>
```

```powershell
$CUSTOMER = "<the id it printed>"
```

The agents of this walkthrough keep their files in `keys/walkthrough`, which git ignores.
A token for one machine, written to the file the first agent reads:

```sh
mkdir -p keys/walkthrough
cargo run -q --release -p ponte-server -- token create $CUSTOMER --out keys/walkthrough/enrollment-token
```

```powershell
New-Item -ItemType Directory -Force keys/walkthrough | Out-Null
cargo run -q --release -p ponte-server -- token create $CUSTOMER --out keys/walkthrough/enrollment-token
```

It prints `token <hash prefix> for customer <id>: 1 machine(s) until <tomorrow>, written to
keys/walkthrough/enrollment-token`. The token itself is only in that file. The audit line
`event="token_issued"` goes to stderr.

## 3. The server

In the server terminal (with `DATABASE_URL` set):

```sh
cargo run -q --release -p ponte-server
```

```
INFO ponte_server: devices left online by the last run marked offline devices=0
INFO ponte_server: server listening bind=127.0.0.1:8080
```

`curl http://127.0.0.1:8080/healthz` answers `ok` (in PowerShell, `curl.exe`).

## 4. The first agent enrolls

The agent's configuration, in the operator terminal:

```sh
cat > keys/walkthrough/agent.toml <<'EOF'
server_url = "ws://127.0.0.1:8080/agent"
allowed_roots = ['C:\FakeErp']
data_dir = "keys/walkthrough/agent"
enrollment_token_file = "keys/walkthrough/enrollment-token"
heartbeat_secs = 60
EOF
```

```powershell
@'
server_url = "ws://127.0.0.1:8080/agent"
allowed_roots = ['C:\FakeErp']
data_dir = "keys/walkthrough/agent"
enrollment_token_file = "keys/walkthrough/enrollment-token"
heartbeat_secs = 60
'@ | Set-Content -Encoding ascii keys/walkthrough/agent.toml
```

In the agent terminal:

```sh
cargo run -q --release -p ponte-agent -- keys/walkthrough/agent.toml
```

```
INFO  agent starting server=ws://127.0.0.1:8080/agent allowed_roots=1 protocol=2 platform="windows"
INFO  action policy actions="disabled" max_risk=Medium max_actions_per_hour=20 min_manifest_interval_secs=600 shutdown_timeout_secs=10
WARN  the configuration names no manifest_keys: this agent runs no action (ADR-0010)
WARN  the device key is stored without encryption ... This build is for development only (ADR-0008)
WARN  server_url is plain ws:// to this machine ... For development only
INFO  new device key stored for an enrollment public_key=...
INFO  enrollment token file removed: the device is enrolled
INFO  enrolled: the server gave this device its id device=<device id>
INFO  connected: the server accepted this device server=ws://127.0.0.1:8080/agent
```

Without `manifest_keys` the agent runs no action; signing manifests is part of M2. The
other two warnings are the point of an M1 build: the key file is not encrypted until M2,
and plain `ws://` is for this machine only. The server logs `event="device_enrolled"`,
`event="session_started"` and `agent connected ... status=Active version=1`.

In the operator terminal:

```sh
cargo run -q --release -p ponte-server -- device list $CUSTOMER
```

```
<device id>  customer <id>  active  online  last seen <now>  agent 0.1.0  <OS name>
```

Devices from earlier runs are listed too, `offline`. Run it again after a minute:
`last seen` moves with every heartbeat.

## 5. A token for many machines waits for approval

A token for two machines, and a second agent that uses it:

```sh
cargo run -q --release -p ponte-server -- token create $CUSTOMER --uses 2 --hours 1 --out keys/walkthrough/second-token
sed -e 's#keys/walkthrough/agent"#keys/walkthrough/second"#' \
    -e 's#enrollment-token"#second-token"#' keys/walkthrough/agent.toml > keys/walkthrough/second.toml
```

```powershell
cargo run -q --release -p ponte-server -- token create $CUSTOMER --uses 2 --hours 1 --out keys/walkthrough/second-token
(Get-Content keys/walkthrough/agent.toml) -replace 'keys/walkthrough/agent"', 'keys/walkthrough/second"' -replace 'enrollment-token"', 'second-token"' | Set-Content -Encoding ascii keys/walkthrough/second.toml
```

In the second agent terminal:

```sh
cargo run -q --release -p ponte-agent -- keys/walkthrough/second.toml
```

It enrolls and connects like the first, and the server logs `status=Pending`. `device list
$CUSTOMER` shows it `pending online`: a device from a token for more than one machine waits
for a person (RF-49). Approve it with its id:

```sh
cargo run -q --release -p ponte-server -- device approve <second device id>
```

It prints `device <id> approved`, and `device list $CUSTOMER` shows it `active`. The
second token still has a use left (`token list` says `1/2 used ... valid`); revoke it,
since nothing else will use it:

```sh
cargo run -q --release -p ponte-server -- token list $CUSTOMER
cargo run -q --release -p ponte-server -- token revoke <its hash prefix>
```

## 6. Revoking a device

```sh
cargo run -q --release -p ponte-server -- device revoke <second device id>
```

It prints `device <id> revoked: a session it has ends within a minute`, and `device list
$CUSTOMER` shows it `revoked offline` at once. Within that minute the session ends, at the
server's next status check:

```
server:        INFO ponte::audit: event="session_ended" device=<id> session=<id> reason=Revoked
second agent:  INFO ponte_agent: session ended end=ServerClosed lasted_secs=60
```

Then the second agent tries again, with growing waits, and every attempt ends the same way:

```
server:        WARN ponte::audit: event="handshake_refused" reason=RevokedDevice device=<id>
second agent:  WARN ponte_agent: the server did not accept this device. It never says why: ...
```

The agent cannot tell a revoked device from one the server does not know, and does not
throw its identity away over it. Stop the second agent with Ctrl+C.

## 7. The server goes away and comes back

Stop the server with Ctrl+C. The first agent logs `session ended end=ServerClosed`, then
`connection failed ... the server cannot be reached: connection refused` with growing waits.
Start the server again:

```sh
cargo run -q --release -p ponte-server
```

```
INFO ponte_server: devices left online by the last run marked offline devices=1
INFO ponte_server: server listening bind=127.0.0.1:8080
```

The sessions of a server that stopped ended without a record, so the device it left
`online` starts offline. Its agent reconnects at the end of its current wait (seconds after
a short outage; waits grow to five minutes at most): the server logs
`event="session_started"`, the agent `connected`, and `device list $CUSTOMER` shows it
`online` again.

## 8. A second server on the same database is refused

In the operator terminal, a second server on another port:

```sh
PONTE_BIND=127.0.0.1:8081 cargo run -q --release -p ponte-server
```

```powershell
$env:PONTE_BIND = "127.0.0.1:8081"; cargo run -q --release -p ponte-server; Remove-Item Env:PONTE_BIND
```

```
Error: the device store could not claim the database for this server: another server is already serving this database
```

It stops at once, without touching the devices: one server per database. The first server
and its agent carry on.

## 9. The agent's footprint (Windows)

With the first agent connected and nothing else running as `ponte-agent`, wait a minute
for it to settle, then measure it for 15 minutes:

```sh
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/measure-agent.ps1 -Binary target/release/ponte-agent.exe -Minutes 15
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\measure-agent.ps1 -Binary target\release\ponte-agent.exe -Minutes 15
```

It prints the binary's size, the peak and average memory, and the CPU over the window,
each against the budget of RNF-12 (under 15 MB, 40 MB and 1%), with numbers written the
way the machine's language writes them. The script only reads the counters of that one
process. On the machine M1 was measured on (Windows 10, 12 logical processors):

```
binary             2.1 MB   (limit 15 MB, within)
process       ponte-agent (pid ...), 90 samples every 10 s, 12 logical processors
working set   avg   14.2 MB, peak   14.4 MB   (limit 40 MB, within)
private bytes avg    8.3 MB, peak    8.6 MB
cpu           0.063 s in 901 s: 0.007% of one core, 0.0006% of the machine   (limit 1%, within)
```

## 10. Clean up

Stop the agent and the server with Ctrl+C, then:

```sh
docker compose -f deploy/docker-compose.yml down     # keeps the data; add -v to drop it
rm -rf keys/walkthrough
```

```powershell
docker compose -f deploy/docker-compose.yml down
Remove-Item -Recurse -Force keys/walkthrough
```
