# Final Local Dashboard Demonstration

This guide records the operator's manual browser verification completed on
2026-11-26 from the original project checkout. It uses loopback services and
the existing Cowrie container probe. It does not require the inaccessible
temporary demo token file or a source copy.

## Verified dashboard results

The operator reported these results from the local run:

- Backend and Vite frontend started from the original project directory.
- Administrator login, logout, and re-login worked.
- Cowrie started in Docker. Three controlled SSH sessions created **15
  genuine Cowrie records**. All 15 were ingested with zero errors and zero
  duplicates.
- The telemetry and Cowrie activity panels rendered. They showed 3 successful
  emulated logins, 6 session events, 0 failed logins, and 0 command attempts.
- Profile recomputation produced one profile with 15 observations:
  **Authentication Probing**, mean anomaly index **0.438**, cluster **4**,
  model `attacker-profile-synthetic-v1`.
- One adaptive deception recommendation was generated. Its local synthetic
  evaluation passed with **8/8 interactions**, **10 synthetic decoys**, and
  **678.5 ms** duration. Explicit approval succeeded.

These are measurements from that controlled local run, not a fresh test run in
this documentation update. Cowrie's successful logins are emulated honeypot
outcomes; they do not indicate access to a real host.

## Prerequisites

- Windows PowerShell, the project's Python environment and dependencies,
  Node/npm, and Docker Desktop with Docker Engine access.
- Start from `D:\Desktop\decentralized-honeypot\decentralized-honeypot`.
- The backend uses the database paths configured by the existing checkout.
  This workflow does not reset them; telemetry ingestion appends new events.
- The synthetic profile model and Cowrie log/cursor are kept outside the
  repository. The profile model is generated once under `%LOCALAPPDATA%` if it
  is missing.

## Terminal 1 — Prepare tokens and start FastAPI

Paste this block in Terminal 1. It generates independent 48-byte random read,
admin, and ingestion tokens, stores them briefly in a uniquely named directory
under `%TEMP%`, and restricts that directory to the current Windows user. It
loads the tokens into this terminal's environment. The script pauses so
Terminal 3 can read the ingestion token file directly; no clipboard transfer
is used between terminals.

```powershell
Set-Location 'D:\Desktop\decentralized-honeypot\decentralized-honeypot'
$repoRoot = (Get-Location).Path
$env:PYTHONPATH = "$repoRoot\backend;$repoRoot"
$env:HONEYPOT_ENV = 'development'

$pythonExe = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) { $pythonExe = 'python' }

$modelDir = Join-Path $env:LOCALAPPDATA 'DecentralizedHoneypot'
New-Item -ItemType Directory -Path $modelDir -Force | Out-Null
$modelPath = Join-Path $modelDir 'attacker_profile_models.joblib'
if (-not (Test-Path -LiteralPath $modelPath)) {
  & $pythonExe -m app.profiling.models_ml `
    --output $modelPath `
    --dataset-output (Join-Path $modelDir 'attacker_profile_synthetic.csv') `
    --samples-per-category 80 --seed 2026
  if ($LASTEXITCODE -ne 0) { throw 'Profile model generation failed.' }
}
$env:HONEYPOT_PROFILE_MODEL_PATH = $modelPath

function New-LocalToken {
  $bytes = New-Object byte[] 48
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes); [Convert]::ToBase64String($bytes) }
  finally { $rng.Dispose() }
}

$tokenDir = Join-Path $env:TEMP ('honeypot-dev-secrets-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tokenDir | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $tokenDir /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict permissions on the temporary token directory.' }

$readFile = Join-Path $tokenDir 'read.token'
$adminFile = Join-Path $tokenDir 'admin.token'
$ingestFile = Join-Path $tokenDir 'ingest.token'
[IO.File]::WriteAllText($readFile, (New-LocalToken))
[IO.File]::WriteAllText($adminFile, (New-LocalToken))
[IO.File]::WriteAllText($ingestFile, (New-LocalToken))
$env:HONEYPOT_API_READ_TOKEN = (Get-Content -LiteralPath $readFile -Raw).Trim()
$env:HONEYPOT_API_ADMIN_TOKEN = (Get-Content -LiteralPath $adminFile -Raw).Trim()
$env:HONEYPOT_TELEMETRY_INGEST_TOKEN = (Get-Content -LiteralPath $ingestFile -Raw).Trim()

Write-Host "Temporary token directory (path only): $tokenDir"
Read-Host 'In Terminal 3, read ingest.token into its environment and prepare Cowrie; then press Enter here'

if (Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) {
  throw 'Port 8000 is occupied. Identify its owner before starting FastAPI.'
}
& $pythonExe -m uvicorn app.main:app --reload --app-dir backend --host 127.0.0.1 --port 8000
```

If the token directory permission command fails, stop and do not continue with
the tokens in that directory. The unique path printed by Terminal 1 is not a
secret; use it as `$tokenDir` in Terminal 3.

## Terminal 2 — Start the React/Vite dashboard

```powershell
Set-Location 'D:\Desktop\decentralized-honeypot\decentralized-honeypot\frontend'
if (Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue) {
  throw 'Port 5173 is occupied. Identify its owner before starting Vite.'
}
npm.cmd run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open `http://127.0.0.1:5173`. The dashboard exchanges the operator's admin
token for a short-lived HttpOnly session; it does not embed the bearer token in
the Vite bundle. To read the token locally for sign-in, open the path printed
by Terminal 1:

```powershell
notepad.exe (Join-Path $tokenDir 'admin.token')
```

Copy it into the sign-in form and close Notepad without saving. After login,
logout and re-login can be checked from the dashboard. Do not place tokens in
Vite environment variables, source files, or chat.

## Terminal 3 — Start Cowrie, generate activity, and ingest

Replace the example `$tokenDir` with the unique path printed by Terminal 1.
This reads the ingestion token from the restricted file directly into the
adapter terminal's environment, without displaying or copying the token.

```powershell
Set-Location 'D:\Desktop\decentralized-honeypot\decentralized-honeypot'
$repoRoot = (Get-Location).Path
$env:PYTHONPATH = "$repoRoot\backend;$repoRoot"
$pythonExe = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) { $pythonExe = 'python' }
$tokenDir = 'C:\Users\<your-user>\AppData\Local\Temp\honeypot-dev-secrets-<run-id>'
$ingestFile = Join-Path $tokenDir 'ingest.token'
$env:HONEYPOT_TELEMETRY_INGEST_TOKEN = (Get-Content -LiteralPath $ingestFile -Raw).Trim()
if (-not $env:HONEYPOT_TELEMETRY_INGEST_TOKEN -or $env:HONEYPOT_TELEMETRY_INGEST_TOKEN.Length -lt 32) { throw 'Ingestion token is missing or invalid.' }

$env:COWRIE_BIND_ADDRESS = '127.0.0.1'
$env:COWRIE_SSH_HOST_PORT = '2222'
docker context show
docker info --format 'Docker Engine {{.ServerVersion}}'
if ($LASTEXITCODE -ne 0) { throw 'Docker Engine is unavailable to this terminal.' }
docker compose -f deploy/cowrie/compose.yaml up -d
if ($LASTEXITCODE -ne 0) { throw 'Cowrie Compose startup failed.' }
docker compose -f deploy/cowrie/compose.yaml ps

Get-Content deploy/cowrie/local_ssh_probe.py -Raw |
  docker exec -i honeypot-cowrie /cowrie/cowrie-env/bin/python3 -
if ($LASTEXITCODE -ne 0) { throw 'The local Cowrie probe failed.' }

$containerId = docker compose -f deploy/cowrie/compose.yaml ps -q cowrie
$labDir = Join-Path $env:LOCALAPPDATA 'DecentralizedHoneypot\cowrie-lab'
New-Item -ItemType Directory -Path $labDir -Force | Out-Null
docker cp "${containerId}:/cowrie/cowrie-git/var/log/cowrie/cowrie.json" (Join-Path $labDir 'cowrie.json')
if ($LASTEXITCODE -ne 0) { throw 'Could not copy the Cowrie JSON log.' }
```

The probe makes three controlled authentication sessions to Cowrie inside its
own container network namespace. It generates invented credentials in memory,
requests no shell, and does not print those credentials. This avoids relying on
the host SSH port, which was not published in the verified Docker Desktop run.
After Terminal 1 has started FastAPI, run the adapter from Terminal 3:

```powershell
& $pythonExe -m app.telemetry.cowrie_cli `
  --log-file (Join-Path $labDir 'cowrie.json') `
  --api-url 'http://127.0.0.1:8000' `
  --sensor-id 'cowrie-local-dev' `
  --token-env 'HONEYPOT_TELEMETRY_INGEST_TOKEN' `
  --cursor-file (Join-Path $labDir 'cowrie.cursor.json')
```

The cursor advances only after accepted or confirmed duplicate responses. Keep
the log and cursor outside the repository. If Cowrie rotates or truncates its
log, inspect the files before using a new cursor; do not silently discard a
cursor while expected records remain.

## Verify the workflow

The operator's 2026-11-26 browser run reported 15 accepted Cowrie records, 0
errors, and 0 duplicates. The dashboard showed 3 successful emulated logins,
6 session events, 0 failed logins, and 0 command attempts. Profile recompute
reported one profile with 15 observations, Authentication Probing, anomaly
index 0.438, cluster 4, and model `attacker-profile-synthetic-v1`.

The operator evaluated one resulting deception recommendation locally: 8/8
interactions, 10 synthetic decoys, 678.5 ms. Approval succeeded. Approval is a
workflow state only; the system does not automatically deploy decoys or
enforce a policy.

The telemetry and Cowrie activity panels were visually verified. **Populated
alerts and incidents panels were not visually verified** in this run; the
observed 0 failed logins and 0 command attempts do not establish an alerting
scenario. The optional network-node dashboard was unconfigured. Use the API
routes `/api/v1/telemetry/alerts`, `/api/v1/incidents`, `/api/v1/profiles`, and
`/api/v1/deception/recommendations` for the corresponding backend views.

## Remove temporary tokens and stop services

After dashboard sign-in and telemetry ingestion, remove only the three token
files created for this run. Run this in Terminal 3, replacing `$tokenDir` with
the path printed by Terminal 1. It leaves the Cowrie log/cursor and named
volume untouched; environment tokens already loaded by the running processes
remain in their process environments until those processes exit.

```powershell
$tokenFiles = @('read.token', 'admin.token', 'ingest.token') |
  ForEach-Object { Join-Path $tokenDir $_ }
Remove-Item -LiteralPath $tokenFiles -Force
Remove-Item -LiteralPath $tokenDir -Force
```

Stop FastAPI and Vite with `Ctrl+C` in their terminals. Stop Cowrie without
deleting its named volume:

```powershell
docker compose -f deploy/cowrie/compose.yaml down
```

## Limitations to state accurately

- The attacker profile model was trained on synthetic data. Its category,
  anomaly index, and cluster are not validated real-world detection metrics.
- The sensor activity was controlled and local. It demonstrates real Cowrie
  log generation and ingestion, not hostile Internet activity or defense
  effectiveness.
- Recommendation evaluation uses synthetic local interactions and decoys.
  Approval does not automatically deploy decoys or change a live policy.
- The optional network dashboard was unconfigured in the manual run.
- Populated alerts and incidents panels were not visually verified.
- `frontend/src/App.jsx` still labels the sidebar **“Simulation mode / Synthetic
  activity only”** even while it displays genuine external Cowrie telemetry.
  That label is misleading for mixed real/simulated activity; this closeout
  documents the issue but does not change frontend behavior.
- The API uses shared local tokens, not individual operator identities. The
  project has no consensus protocol or production-grade multi-machine
  availability.
