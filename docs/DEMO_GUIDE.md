# Local demonstration guide

Use an isolated lab on loopback. Do not use real credentials or expose the
services to the public Internet.

## Start API and dashboard

From the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
python -m uvicorn app.main:app --reload --app-dir backend
```

In a second shell:

```powershell
Set-Location frontend
npm.cmd run dev -- --host 127.0.0.1
```

The API docs are at `http://127.0.0.1:8000/docs`; the dashboard is usually at
`http://127.0.0.1:5173`. With no API tokens, local development mode is open.
For a protected local API, configure distinct random
`HONEYPOT_API_READ_TOKEN` and `HONEYPOT_API_ADMIN_TOKEN` values in the backend
shell. The dashboard asks for the admin token at runtime and exchanges it for
a short-lived session; no token belongs in Vite configuration. Configure a
separate `HONEYPOT_TELEMETRY_INGEST_TOKEN` before using external adapters.
Never put admin or ingestion tokens in a Vite variable.

PowerShell can verify the session flow without invoking any modifying API:

```powershell
$webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$login = Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/auth/session" `
  -WebSession $webSession -ContentType "application/json" `
  -Body (@{ admin_token = $env:HONEYPOT_API_ADMIN_TOKEN } | ConvertTo-Json)
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/simulation/scenarios" -WebSession $webSession
Invoke-RestMethod -Method Delete `
  -Uri "http://127.0.0.1:8000/api/v1/auth/session" `
  -WebSession $webSession -Headers @{ "X-CSRF-Token" = $login.csrf_token }
```

## Demonstrate interaction, adaptation, and a synthetic bundle

```powershell
$actorId = "demo-actor-$([guid]::NewGuid().ToString('N'))"
$interaction = @{ actor_id = $actorId; action = "attempt_login" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/decoys/decoy-credential-001/interactions" -ContentType "application/json" -Body $interaction
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/adaptation/$actorId"
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/bundles/generate/$actorId?scenario_id=demo"
```

The returned assets are synthetic disabled examples; no real service or login
is created.

## Demonstrate passive telemetry adapters

Configure an explicit loopback API URL, sensor ID, token environment
variable, and cursor file. Run the Zeek, Suricata, or Cowrie adapter commands
in the root README against a local sample or restricted sensor log. A dry run
is supported by the Suricata and Cowrie CLIs. The adapters never execute log
contents. Cursor reset after rotation must follow the instructions for that
adapter; do not discard a cursor until the old file's remaining records are
accounted for.

### Generate real local Cowrie events and trace them into profiles

This walkthrough creates genuine events from the pinned Cowrie container, then
copies its JSON log outside the repository and imports it through the passive
adapter. It is distinct from simulator-generated events and fixtures. Cowrie
binds SSH only on loopback; use synthetic login names/passwords.

#### Verification record (2026-11-16)

The runtime prerequisite was checked with:

```powershell
docker --version
docker info --format '{{.ServerVersion}}'
docker compose -f deploy/cowrie/compose.yaml config
```

Docker CLI reported `29.2.1` and Compose configuration rendered, but `docker
info` could not connect to `npipe:////./pipe/docker_engine` because the pipe
was not found and the daemon was not running. Cowrie was not started, no SSH
activity was generated, and no sensor-generated event was ingested in this
verification. Start Docker Engine and rerun the steps below before claiming a
live sensor demonstration. Docker also warned that the user's Docker config
file was inaccessible; no Docker configuration was changed.

Start Cowrie using the README's `deploy/cowrie/compose.yaml` commands. From a
PowerShell window, initiate a local SSH attempt and enter an invented password
at the prompt:

```powershell
ssh.exe -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL `
  -o PreferredAuthentications=password -o PubkeyAuthentication=no `
  -o NumberOfPasswordPrompts=1 lab-user@127.0.0.1
```

Repeat after each failed login to produce at least three failed-auth events.
Stop after each failure returns to the shell; this command only connects to
the local Cowrie container. Copy its JSON log to a restricted directory
outside the repository using README's Cowrie instructions.

Configure the local node's `publication_policy` explicitly. Map
`cowrie_login_failed` to `brute_force`, set `minimum_severity` to `medium`,
`minimum_observations` to `3`, allow only `cowrie`, and enable collection.
Cowrie will often see a private Docker bridge address; keep
`require_global_ip=true` to reject it by default. Only for an isolated demo,
an operator may set it false to observe local records passing the gate. This
can create a signed private-address claim and must not be used as a real
sharing policy.

In the backend API shell, configure the dedicated ingestion token and
server-side `HONEYPOT_INTEL_COLLECTOR_URL` / `HONEYPOT_INTEL_COLLECTOR_TOKEN`
(the token must match that node's admin token), then start the backend. In the
adapter shell, set the same telemetry token and run
`python -m app.telemetry.cowrie_cli` against the copied log with an explicit
API URL, sensor ID, and cursor path. Accepted records are stored in the event
ledger first. The optional collector forwards only source system, sensor and
event references, time, type, severity, and source IP; raw Cowrie fields are
not sent to the node. Collector unavailability does not discard a ledgered
event.

Train the trusted local profile model if its artifact is not already present,
then call `POST /api/v1/profiles/recompute` with a window covering the log
timestamps. Profiles aggregate external events by source IP and store a
pseudonymous source reference. Inspect `GET /api/v1/profiles` and the node's
`GET /v1/intelligence` with their respective credentials. An intelligence
record remains a claim, not verified truth or an enforcement action. Node
collection is disabled and unmapped by default; confidence is a disclosed
heuristic rather than a probability.

## Demonstrate live node replication and trust management

Run the actual two-process localhost demonstration from the repository root:

```powershell
$repoRoot = (Get-Location).Path
$env:PYTHONPATH = "$PWD\backend;$PWD"
python -m app.network.live_demo
```

The runner creates separate test keys, configs, databases, and Uvicorn
processes; it sends signed intelligence over loopback HTTP, tests pending and
duplicate behavior, rejects tampering, takes Node B offline, restarts it, and
checks recovery. It is a local process demonstration, not multi-machine
deployment or consensus. For the manual two-terminal configuration, peer
management, key rotation, approval, and audit commands, see
[Node replication](NODE_REPLICATION.md).

## Review and decide on received intelligence

On the receiving node, inspect records and provenance, then explicitly approve
or reject a pending record. Approval records local review state only; it does
not block an address or deploy a honeypot. Record expiry, duplicate/conflict
handling, and confidence-score limitations are described in
[Node replication](NODE_REPLICATION.md) and [Security](SECURITY.md).

## Compare static and adaptive deception

Use the dashboard's **Adversary experiments** section or `POST
/api/v1/experiments/run` with a fixed seed and both `baseline` and `adaptive`
modes. The harness runs deterministic synthetic scenarios and reports
measured detector coverage, false positives/negatives, capture, latency, and
strategy selections. It also reports an explicit seeded reaction-model
engagement rate, synthetic interaction depth, and virtual event duration.
Unique decoys accessed is returned as unavailable because those events do not
contain decoy asset IDs. The simulated engagement probability is a scenario
assumption; these results do not measure real attackers, dwell time, or
real-world effectiveness.

## Run controlled experiments

`POST /api/v1/experiments/run` accepts seeded synthetic scenarios and modes
`baseline`, `adaptive`, and optionally `closed_loop`. See
[Experimental Evaluation](EXPERIMENTAL_EVALUATION.md) for request examples and
metric definitions. Results are synthetic software measurements, not
real-world detection accuracy or attacker behavior.
