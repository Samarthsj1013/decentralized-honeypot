# Decentralized AI Self-Evolving Honeypot Network

An experimental cybersecurity research prototype for adaptive honeypots,
behavioral threat analysis, and decentralized threat intelligence.

## Project Status

Prototype: the current behavior-conditioned policy is deterministic and
rule-based. It does not implement a GAN, reinforcement learning, or live
network enforcement. Scenario evaluations use synthetic interactions.

## Research Goals

- Build a controlled honeypot environment.
- Analyze decoy interaction events.
- Develop and evaluate a conditional generative decoy model.
- Compare learned adaptation policies with the deterministic baseline.
- Investigate privacy-preserving, authenticated cross-organization sharing.
- Evaluate deception outcomes with controlled attacker-facing measures.

## Safety

Testing is restricted to authorized, isolated environments and synthetic data.
The current architecture, security assumptions, implementation status, and
reproducible demo/test instructions are summarized in
[the project audit](docs/PROJECT_AUDIT.md), [security notes](docs/SECURITY.md),
[architecture](docs/ARCHITECTURE.md), [implementation status](docs/IMPLEMENTATION_STATUS.md),
[testing guide](docs/TESTING.md), [demo guide](docs/DEMO_GUIDE.md),
[final demo guide](docs/FINAL_DEMO_GUIDE.md), and
[final placement status](docs/FINAL_PLACEMENT_STATUS.md).

## API access control and dashboard sessions

The API supports optional shared bearer tokens for local deployments. Set
`HONEYPOT_API_READ_TOKEN` for GET/HEAD access and
`HONEYPOT_API_ADMIN_TOKEN` for all API methods. Use independently generated
random values of at least 32 characters. An admin token can also perform reads.
When either token is configured, invalid or missing credentials are rejected;
a configured token shorter than 32 characters, or identical reader/admin
tokens, makes API requests return 503.
The telemetry ingestion endpoint remains separately protected by
`HONEYPOT_TELEMETRY_INGEST_TOKEN`.

With no API tokens configured, the backend keeps its development-compatible
open mode, which the UI labels and does not represent as an authenticated
session. Uvicorn's documented command binds to loopback by default; do not
expose the app to untrusted networks in open mode. To configure local tokens:

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
$env:HONEYPOT_API_READ_TOKEN = "use-a-random-read-token-at-least-32-characters"
$env:HONEYPOT_API_ADMIN_TOKEN = "use-a-different-random-admin-token-32-chars"
python -m uvicorn app.main:app --reload --app-dir backend
```

Command-line API clients may pass `Authorization: Bearer <token>`. The browser
dashboard does not inject reader or node bearer tokens from Vite variables.
Instead, an operator enters the backend admin token at sign-in; the backend
exchanges it for a 30-minute `HttpOnly`, `SameSite=Strict` session cookie.
Mutating browser requests also send a CSRF token held in memory. Sign-out
invalidates the server-side session. The session store and login throttling are
process-local and sessions end on backend restart. This is shared-token
administrator access, not user accounts or per-user identity/auditing.

For production, use HTTPS and set
`HONEYPOT_SESSION_COOKIE_SECURE=true`. Keep the UI and API on the same host
name (for example, both `127.0.0.1`) so the strict cookie is sent. The optional
node operations panel is proxied server-side by the backend; configure
`HONEYPOT_NODE_DASHBOARD_URL` and `HONEYPOT_NODE_DASHBOARD_TOKEN` only in the
backend environment. These variables and node credentials must never use a
`VITE_` prefix. The session endpoint still exchanges the configured shared
admin token; it does not create separate user identities.

## Local setup

From the repository root, install backend dependencies and start FastAPI:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
python -m uvicorn app.main:app --reload --app-dir backend
```

The API documentation is at `http://127.0.0.1:8000/docs`. To run the Vite
dashboard in a second PowerShell window:

```powershell
Set-Location frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173` and sign in with the backend's admin token. Set
`HONEYPOT_NODE_DASHBOARD_URL` and `HONEYPOT_NODE_DASHBOARD_TOKEN` in the
backend shell if the optional local node panel should display node data.

`GET /health` reports backend availability, persisted ledger connectivity and
integrity, whether the local profile model and telemetry token are configured,
whether API access tokens are enabled, and that external adapters are not
probed by the backend. It does not expose token values or local file paths. A
degraded ledger check returns HTTP 503; an unavailable profile model is shown
as a component status but does not make the core API unavailable.

Frontend checks are `npm test` and `npm run build` from `frontend`. Backend
tests initialize SQLite and the ledger checkpoint key through application
imports. Run them using the source-only temporary-copy instructions below so
test stores and keys remain isolated from local application data.

## Synthetic decoy bundles

Behavior-conditioned strategy changes create version 1 bundles from a single
canonical synthetic entity. The related identity, database record, file, and
API representation share the same synthetic employee and project identifiers.
Bundle relationships are validated before persistence. The bundle and its
legacy decoy-list projections are written in one SQLite transaction. Values
are marked as disabled or test-only and are not valid credentials.

After recording an interaction, generate a bundle with:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/decoys/decoy-credential-001/interactions" `
  -ContentType "application/json" `
  -Body '{"actor_id":"demo-actor-001","action":"attempt_login"}'
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/bundles/generate/demo-actor-001?scenario_id=demo"
```

The response includes a consistency result and projected decoy IDs. Retrieve
the persisted bundle and validate it without changing state:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/bundles/bundle-<id>"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/bundles/bundle-<id>/validation"
```

A bundle is structured as follows (identifiers and values here are examples):

```json
{
  "bundle_id": "bundle-example",
  "schema_version": 1,
  "actor_id": "demo-actor-001",
  "selected_strategy": "credential_decoy",
  "strategy_reason": "Synthetic login behavior observed",
  "fingerprint_version": 1,
  "canonical_entities": [{
    "entity_id": "bundle-example-entity",
    "employee_id": "EMP-TEST001",
    "synthetic_name": "Synthetic Employee TEST001",
    "department": "Research Sandbox",
    "project_code": "LAB-TEST001",
    "service_identity": "synthetic_service_test001",
    "synthetic_only": true
  }],
  "identities": [{
    "asset_id": "bundle-example-identity",
    "entity_id": "bundle-example-entity",
    "employee_id": "EMP-TEST001",
    "synthetic_name": "Synthetic Employee TEST001",
    "department": "Research Sandbox",
    "project_code": "LAB-TEST001",
    "service_identity": "synthetic_service_test001",
    "authentication_state": "DISABLED_SYNTHETIC"
  }],
  "api_resources": [{
    "asset_id": "bundle-example-api",
    "entity_id": "bundle-example-entity",
    "method": "GET",
    "resource_path": "/synthetic/api/v1/entities/test001",
    "representation": {
      "employee_id": "EMP-TEST001",
      "department": "Research Sandbox",
      "project_code": "LAB-TEST001",
      "service_identity": "synthetic_service_test001"
    }
  }],
  "relationships": [
    {"source_asset_id": "bundle-example-entity", "relationship": "has_identity", "target_asset_id": "bundle-example-identity", "relationship_key": "bundle-example-identity-link"},
    {"source_asset_id": "bundle-example-entity", "relationship": "exposed_as_api_resource", "target_asset_id": "bundle-example-api", "relationship_key": "bundle-example-api-link"}
  ],
  "synthetic_only": true
}
```

The actual API response also includes generated timestamps, strategy rationale,
fingerprint version, and the remaining modeled entity fields. The independent
validator reports schema, identifier, reference, and cross-asset consistency
issues; successful validation means internal synthetic-data consistency only.

## Live telemetry ingestion and alerting

The external ingestion endpoint accepts a bounded, normalized JSON envelope
and treats its contents only as data. It does not execute fields, commands, or
network actions. The request is limited to 32 KiB, rejects unknown fields,
requires timezone-aware timestamps, constrains network fields, and bounds
arbitrary JSON `attributes` by size, depth, and value count.

External ingestion is disabled until a bearer token is configured. Keep the
token out of source control and set it in the same PowerShell session used to
start the local backend:

```powershell
$env:HONEYPOT_TELEMETRY_INGEST_TOKEN = "replace-with-a-long-random-local-token"
python -m uvicorn app.main:app --reload --app-dir backend
```

`POST /api/v1/telemetry/ingest` requires `Authorization: Bearer <token>`. The
normalized envelope uses `source_system` (`generic`, `zeek`, or `suricata`),
`sensor_id`, `external_event_id`, `occurred_at`, `event_type`, and optional
severity, IP/port/protocol fields, and JSON `attributes`. For example:

```powershell
$headers = @{ Authorization = "Bearer $env:HONEYPOT_TELEMETRY_INGEST_TOKEN" }
$event = @{
  source_system = "generic"
  sensor_id = "lab-sensor-01"
  external_event_id = "event-0001"
  occurred_at = "2026-11-02T12:00:00Z"
  event_type = "port_scan_detected"
  severity = "high"
  source_ip = "192.0.2.15"
  destination_ip = "198.51.100.9"
  protocol = "tcp"
  attributes = @{ count = 12 }
} | ConvertTo-Json -Depth 6
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/telemetry/ingest" `
  -Headers $headers -ContentType "application/json" -Body $event
```

An initial accepted event returns HTTP 201; an exact replay returns HTTP 200
with `duplicate: true`, and reuse of the same sensor/event ID with changed
contents returns HTTP 409. Event IDs are derived deterministically from the
source system, sensor ID, and external event ID. Accepted events are marked
`source: external`, stored in the existing event store, and appended to the
existing hash-chain ledger. At startup, the event store is rehydrated from the
ledger, allowing deduplication to survive process restarts.

When both backend-only `HONEYPOT_INTEL_COLLECTOR_URL` and
`HONEYPOT_INTEL_COLLECTOR_TOKEN` are configured, the ingest route sends the
node only a bounded source/sensor/event/time/type/severity/IP projection after
ledger persistence. The response includes an `intelligence_collection` status
(`disabled`, `misconfigured`, `unavailable`, `not_eligible`, or `evaluated`
with the node's policy outcome). Collector failures do not roll back accepted
telemetry. The node's own publication policy remains disabled by default and
must explicitly map event types, sources, severity, and observation count.
This is an opt-in handoff, not an implicit subscription or automatic blocklist.

Alerts use a small deterministic rule set: high/critical severity or selected
suspicious event-type markers create an alert. This is triage plumbing, not a
trained detector or an effectiveness claim. Read current alerts from
`GET /api/v1/telemetry/alerts?limit=30`. `GET /api/v1/telemetry/stream` is an
SSE feed that sends recent event summaries and subsequent event/alert updates;
the live projection omits raw attributes and IP addresses. Alerts and SSE
subscriber queues are in-memory and bounded, so alerts are rebuilt from
restored external events at process startup and live clients may miss updates
if a queue overflows while disconnected.

The `suricata` adapter reads newline-delimited EVE JSON from a file and sends
normalized events through the same authenticated ingestion endpoint. It
supports `alert`, `flow`, `dns`, `http`, `tls`, `ssh`, and `fileinfo` records.
It keeps only a bounded allowlist of useful fields; raw packets, payloads,
cookies, HTTP URL query strings/fragments, arbitrary nested data, and unrelated
EVE keys are not forwarded.
Suricata numeric alert severity 1 maps to high, 2 to medium, and 3 or higher to
low. Non-alert event types always map to low and are not automatically treated
as suspicious. EVE `alert` records use the existing alert/dashboard pipeline
even when the source severity is low; the original severity is retained on the
alert, and routine `flow`, `dns`, and other records do not create alerts.

Sample EVE JSON record:

```json
{"timestamp":"2026-11-05T10:15:30.125000+0000","event_type":"alert","src_ip":"192.0.2.10","src_port":51514,"dest_ip":"198.51.100.20","dest_port":443,"proto":"TCP","alert":{"signature":"ET SCAN Suspicious inbound connection","category":"Attempted Information Leak","severity":1,"signature_id":2001234}}
```

Run the adapter from PowerShell after installing the backend requirements and
starting the API. The URL, sensor ID, token environment-variable name, and
cursor path are explicit; the credential itself is read from the environment.

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
$env:HONEYPOT_TELEMETRY_INGEST_TOKEN = "replace-with-a-long-random-local-token"
python -m app.telemetry.suricata_cli `
  --log-file "D:\suricata\eve.json" `
  --api-url "http://127.0.0.1:8000" `
  --sensor-id "suricata-lab-01" `
  --token-env "HONEYPOT_TELEMETRY_INGEST_TOKEN" `
  --cursor-file "D:\suricata\state\eve.cursor.json"
```

Use `--dry-run` to parse and summarize without sending events or changing the
cursor; it still requires an explicit API URL, sensor ID, and token-variable
name, but does not require the environment variable to be populated. Normal
runs report records read, new accepts, confirmed duplicates, alert counts, and
event-type counts. A completed EVE line advances the cursor only after HTTP
201 or confirmed duplicate HTTP 200. API failures stop at the failed record;
malformed records are reported by byte offset without printing their contents,
and the cursor remains before them so they are not silently discarded.

The cursor is tied to the resolved input path, configured API URL, and sensor
ID. Use a separate cursor for each rotated log file. A file shorter than its
saved cursor is rejected; create a new cursor after verifying a rotation or
truncation. If a file is replaced in place with a file at least as large as the
old one, the adapter cannot reliably identify that replacement, so operators
must rotate the cursor with the file. The adapter is passive: it does not
install/manage Suricata, follow the file continuously, execute EVE content, or
perform network enforcement. Unknown event types retain only their type name.

A standalone Zeek `conn.log` adapter is available as
`python -m app.telemetry.zeek_cli`. It reads Zeek TSV using `#separator`,
`#fields`, `#types`, `#unset_field`, and `#empty_field` directives, and also
accepts newline-delimited Zeek JSON. It maps `uid` to the external event ID (or
a stable record digest if `uid` is absent), endpoints and protocol to
normalized network fields, and service/state/duration/byte counts to
attributes. Missing Zeek values remain absent. This is a file adapter only; it
does not install or configure Zeek and does not provide a Zeek agent.

Configure the API address, sensor identity, and secret explicitly. The bearer
token is read from the named environment variable and is never placed in the
command line or source:

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
$env:HONEYPOT_TELEMETRY_INGEST_TOKEN = "replace-with-a-long-random-local-token"
python -m app.telemetry.zeek_cli `
  --log-file "D:\zeek\logs\current\conn.log" `
  --api-url "http://127.0.0.1:8000" `
  --sensor-id "zeek-lab-01" `
  --token-env "HONEYPOT_TELEMETRY_INGEST_TOKEN" `
  --cursor-file "D:\zeek\state\conn.cursor.json"
```

The cursor stores the byte offset and TSV headers, advancing each complete
record only after HTTP 200 (confirmed duplicate) or 201 (new event). Re-running
the command resumes from that point; server-side deduplication also protects
retries after an accepted event whose response was lost. Use a separate cursor
for each rotated log file. If a log is truncated/rotated in place, start with a
new cursor after verifying the intended input file. A changed record reusing a
Zeek UID is rejected by the API as a conflict and stops processing for review.
For JSON, the adapter expects one Zeek object per line. The adapter only parses
and forwards records to the explicitly configured API; it rejects API URLs
with user info/query/fragment values and refuses redirects so the bearer token
cannot be forwarded to a different host. It never executes log contents or
initiates scanning.

## Cross-source incident correlation

Accepted external Zeek and Suricata events with a valid source IP are also
checked by a bounded, deterministic correlation service. The default window is
300 seconds and can be changed with `HONEYPOT_CORRELATION_WINDOW_SECONDS`
(valid range 1–3600). The service does not correlate simulator or generic
events. It recognizes repeated Suricata alerts, a Suricata alert followed by
at least two Zeek connections, at least three Zeek connections, activity to at
least three destination ports, multiple distinct sensor IDs, and an event
whose severity rises above all earlier events in the window. Two source types
using the same configured sensor ID do not count as separate sensors. These
are investigation signals, not proof of compromise or a trained detection model.

Each active rule has a documented fixed evidence score: multi-sensor 0.45,
repeated Zeek connections 0.55, multiple destination ports 0.60, repeated
Suricata alerts 0.70, alert-followed-by-connections 0.75, and severity
escalation 0.85. When several rules match, the highest score plus 0.05 per
additional rule is used, capped at 0.95. This number measures configured rule
evidence only; it is not a statistically calibrated probability. Incident
severity is the higher of the strongest observed input severity and the
applicable rule floor (high for alert/escalation combinations, medium for
other correlations). Evidence is stored as bounded event IDs, sensor labels,
rule identifiers, and fixed explanatory summaries. Raw telemetry attributes,
payloads, actor IDs, and credentials are not copied into the incident store.

Incidents persist in a dedicated additive SQLite database at
`data/incidents.sqlite3` (or `HONEYPOT_INCIDENT_DB_PATH`). The directory and
tables are created on first incident-store use, not merely by importing the
module. Recent correlation candidates are pruned to the configured time window
and capped at 10,000 rows; each incident retains at most 200 event IDs, 32
sensors, and 12 rules/summaries. Incident records remain until manually
managed in the database; the API does not provide deletion. Status transitions
are explicit: acknowledge open incidents or resolve open/acknowledged ones.
New matching evidence reopens a resolved incident. These actions are workflow
state only and do not block traffic, scan systems, alter firewall policy, or
enforce a response.

Endpoints:

- `GET /api/v1/incidents?limit=50&offset=0&status=open&severity=high` returns a
  bounded page. `source_ip` can also be used as a filter.
- `GET /api/v1/incidents/{incident_id}` returns one incident.
- `GET /api/v1/incidents/stats` returns total, status, and severity counts.
- `POST /api/v1/incidents/{incident_id}/acknowledge` and `/resolve` record
  explicit workflow actions; acknowledging a resolved incident returns 409.

Example local review:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/incidents/stats"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/incidents?limit=20&status=open"
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/incidents/INCIDENT_ID/acknowledge"
```

The dashboard shows persisted incident counts and evidence from these API
responses. Configure the optional reader/admin API tokens above before
exposing these endpoints to untrusted networks. Correlation is local to this
process's configured SQLite store and does not replicate incidents across
organizations.

## Cowrie SSH honeypot (controlled local lab)

`deploy/cowrie/compose.yaml` runs the official [`cowrie/cowrie`](https://github.com/cowrie/cowrie)
image, pinned here to release `v3.1.5`. It runs as UID/GID 999, drops Linux
capabilities, enables `no-new-privileges`, uses a read-only container root with
bounded temporary filesystems, sets CPU/memory/process limits, and uses an
internal Docker network to deny general container egress. Compose requests an
SSH host mapping on `127.0.0.1:2222` by default, but the verified Docker
Desktop run did not publish that mapping. The verified probe therefore ran
inside Cowrie and connected only to its own loopback. Do not broaden the bind
to work around this environment-specific limitation. Cowrie's writable state
is held in a Docker named volume; no host credentials, project directories, or
Docker socket are mounted. These settings follow the official [Cowrie Docker image
and install guidance](https://docs.cowrie.org/en/latest/INSTALL.html).

Start from the repository root with Docker Compose installed:

```powershell
$env:COWRIE_BIND_ADDRESS = "127.0.0.1"
$env:COWRIE_SSH_HOST_PORT = "2222"
docker compose -f deploy/cowrie/compose.yaml up -d
docker compose -f deploy/cowrie/compose.yaml ps
```

In the verified Docker Desktop setup, the configured host port was not
published. The repeatable demonstration uses the bounded probe inside the
Cowrie container and sends no connection to a host or public service. Do not
change the bind to `0.0.0.0` to work around this limitation. The internal
network prevents the Cowrie container from making arbitrary outbound
connections; the API/adapter runs separately on the host. See
[`docs/FINAL_DEMO_GUIDE.md`](docs/FINAL_DEMO_GUIDE.md) for the verified probe
and the restricted temporary-token-file startup procedure.

Cowrie JSON logs include sensitive attacker-submitted values by design. Copy
the JSON audit log to a restricted location outside the repository; do not
commit, share, or display that raw file. Cowrie's official Docker image stores
JSON events at `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`. To copy a
snapshot from the named volume, choose an operator-controlled local path:

```powershell
$containerId = docker compose -f deploy/cowrie/compose.yaml ps -q cowrie
docker cp "${containerId}:/cowrie/cowrie-git/var/log/cowrie/cowrie.json" "D:\CowrieLab\cowrie.json"
```

Set the same local telemetry bearer token in the API and adapter shells. The
API shell starts the existing backend; the second shell runs the passive
adapter against the restricted copy:

```powershell
# API terminal
$env:PYTHONPATH = "$PWD\backend;$PWD"
$env:HONEYPOT_TELEMETRY_INGEST_TOKEN = "set-a-local-random-token-of-at-least-32-bytes"
$env:HONEYPOT_API_ADMIN_TOKEN = "set-a-different-random-admin-token-of-at-least-32-bytes"
# Optional: point the collector at a configured node; these values stay backend-side.
$env:HONEYPOT_INTEL_COLLECTOR_URL = "http://127.0.0.1:8101"
$env:HONEYPOT_INTEL_COLLECTOR_TOKEN = $env:NODE_A_ADMIN_TOKEN
# Optional: backend-side read-only node dashboard proxy credentials.
$env:HONEYPOT_NODE_DASHBOARD_URL = "http://127.0.0.1:8101"
$env:HONEYPOT_NODE_DASHBOARD_TOKEN = $env:NODE_A_DASHBOARD_READ_TOKEN
python -m uvicorn app.main:app --reload --app-dir backend
```

```powershell
# Adapter terminal; set the same token locally, without saving it in the repo
$env:PYTHONPATH = "$PWD\backend;$PWD"
$env:HONEYPOT_TELEMETRY_INGEST_TOKEN = "set-a-local-random-token-of-at-least-32-bytes"
python -m app.telemetry.cowrie_cli `
  --log-file "D:\CowrieLab\cowrie.json" `
  --api-url "http://127.0.0.1:8000" `
  --sensor-id "cowrie-lab-01" `
  --token-env "HONEYPOT_TELEMETRY_INGEST_TOKEN" `
  --cursor-file "D:\CowrieLab\cowrie.cursor.json"
```

Run once with `--dry-run` to inspect counts without sending records or changing
the cursor. The API URL, sensor ID, and cursor are explicit; the bearer token
is obtained only from the named environment variable. The adapter accepts
Cowrie JSON lines, advances its atomic cursor only after HTTP 201 or a confirmed
duplicate HTTP 200, and stops at malformed records or API errors. The adapter
derives the external event ID from a SHA-256 digest of the source line, while
server-side deduplication combines source system, sensor ID, and that event ID.
The raw line is not forwarded; this digest is a stable event key, not
anonymization. The cursor also verifies the file path, initial prefix, API,
and sensor to catch common rotation/replacement mistakes. If a log rotates or
truncates, stop and inspect the files, then choose a new cursor for the new
log; do not blindly remove a cursor while the old log is still expected to
resume. The CLI never follows redirects with the bearer token.

The adapter maps Cowrie login success/failure, session connect/close, command
attempt, upload/download, session parameters, and client-version/fingerprint
events. It includes a deterministic sensor-scoped SHA-256 username reference
and bounded network metadata, but never includes raw usernames, passwords,
raw commands or command output, URLs, filenames, or uploaded file contents.
Username references are pseudonymous and can be guessed for common names.
Session identifiers are one-way hashed. Command attempts retain only
their presence and input length; file transfer events retain direction and
safe digest/size metadata. Unknown Cowrie events are labeled `cowrie_other`
with the bounded event name retained. This is JSON file ingestion, not a live
Cowrie agent or a control channel.

Cowrie incident rules flag at least three failed logins, a success after at
least three failures, three command attempts in one hashed session, three
session starts from one IP, Cowrie session activity sharing a source IP and
window with Zeek connections, or Cowrie activity sharing a source IP/window
with a Suricata alert. A successful login after failures is a suspicious
signal, not evidence that the host was compromised. Rule confidence remains a
fixed evidence score, not calibrated probability. Dashboard Cowrie counters
describe the latest 30 events returned/streamed, not lifetime totals; summaries
show source IP, event type, time, authentication result, and hashed session
reference only. Passwords and command content are not displayed.

Stop Cowrie while retaining its named-volume logs and state:

```powershell
docker compose -f deploy/cowrie/compose.yaml down
```

Do not add `-v` unless intentionally deleting Cowrie's stored audit/state
volume. Public exposure, malicious file execution, automated blocking, and
attacker retaliation are not implemented.

## ML attacker behavior profiles and adaptive recommendations

The telemetry profile pipeline is separate from the existing simulator actor
classifier and does not change its API. It groups accepted external Zeek,
Suricata, and Cowrie events by source IP in a configurable 60–86,400 second
observation window. Profile IDs and source references are deterministic
SHA-256 hashes of the source IP. This is pseudonymization for local display,
not anonymization or resistance to address guessing. Raw source addresses,
event IDs, usernames, passwords, commands, file paths, and event payloads are
not copied into profile records. Cowrie ingestion stores a sensor-scoped hash
reference instead of raw usernames; profile output retains only its measured
cardinality.

Feature schema `decentralized_honeypot.attacker_behavior_features` v1 contains
event counts; failed/successful authentication counts; unique username count;
session and command-attempt counts; destination-port and connection counts;
connection rate; Suricata alert and severity counts; available session-duration
statistics; SSH/TCP/UDP/ICMP/other event counts; unique protocol and sensor
counts; mean time between authentication/command attempts; normalized
event-type diversity; and bounded incident/severity/rule counts from the
separate incident store. Incident text, evidence, and event IDs are not features.
Missing measurements use zero-valued features only with
explicit availability indicators where needed (`session_duration_available`
and `inter_attempts_available`). Feature definitions are in
`backend/app/profiling/features.py`.

Train the versioned RandomForestClassifier, IsolationForest, and KMeans models
from the repository root. Labels are generated only by the seeded synthetic
dataset generator; live telemetry is never silently labeled for training.
Keep the resulting joblib artifact in a trusted local path and do not load
artifacts supplied by an untrusted source:

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
python -m app.profiling.models_ml `
  --output "experiments\results\attacker_profile_models.joblib" `
  --dataset-output "experiments\results\attacker_profile_synthetic.csv" `
  --samples-per-category 80 `
  --seed 2026
```

The model metadata records artifact, feature, and model versions, synthetic
training source, class labels, sample count, seed, and the anomaly model's
synthetic reference distribution. `RandomForestClassifier` predicts one of
reconnaissance, authentication probing, repeated connection, suspicious
session, multi-protocol, or unknown. The Random Forest vote fraction is not a
calibrated probability. IsolationForest produces a relative anomaly index
against its synthetic baseline, not a probability or maliciousness score.
KMeans assigns a synthetic feature-space cluster. A model's global feature
importances are displayed as explanatory context; they are not causal
per-event attributions. Insufficient or incompatible model artifacts result
in HTTP 503 from recompute; the API does not train models.

Recompute profiles after ingesting sensor events:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/profiles/recompute" `
  -ContentType "application/json" `
  -Body '{"window_seconds":3600}'
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/profiles?limit=50"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/profiles/stats"
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/profiles/PROFILE_ID"
```

Profiles persist separately in `data/attacker_profiles.sqlite3`; set
`HONEYPOT_PROFILE_DB_PATH` to select another local SQLite file. Recompute
history is capped at 20 snapshots per profile. The default model artifact is
`experiments/results/attacker_profile_models.joblib`; the optional local
`HONEYPOT_PROFILE_MODEL_PATH` setting can point to another trusted artifact.
The profile database is initialized on first use, not on module import.

Recommendations are deterministic, rule-constrained proposals informed by the
ML category and aggregate features. Reconnaissance-like profiles suggest more
varied simulated paths; authentication-probing profiles suggest disabled
synthetic login targets; repeated-connection profiles suggest varied
simulated responses; session and multi-protocol categories suggest additional
inert synthetic assets or observability. Unknown/insufficient profiles only
suggest collecting more telemetry. Recommendations never execute commands,
use captured credentials, expose a service, change a firewall, or automatically
deploy a decoy.

Evaluate and explicitly approve a recommendation with separate calls:

```powershell
$recommendations = Invoke-RestMethod "http://127.0.0.1:8000/api/v1/deception/recommendations?limit=50"
$recommendationId = $recommendations.items[0].recommendation_id
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/deception/recommendations/$recommendationId/evaluate"
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/deception/recommendations/$recommendationId/approve"
```

Local evaluation invokes the existing five-scenario simulation pipeline with
temporary event, ledger, decoy, adaptation, simulation, and evaluation stores.
It reports measured scenario completion, interaction recording, generated
decoys, bundle validation, and elapsed time. Approval requires complete runs,
fully recorded interactions, valid bundles, sufficient profile evidence, and
the expected synthetic scenario being present. Telemetry-source coverage and
real-world false-positive risk are explicitly unavailable because the
simulator does not emit native sensor traffic and no labeled real-world
validation set exists. A passing evaluation validates this local workflow; it
does not establish detection accuracy or deception effectiveness. Approval
records review state only and does not activate enforcement or deployment.

Dashboard profile, anomaly-index, cluster, recommendation, evaluation, and
approval views use the corresponding `/api/v1/profiles` and
`/api/v1/deception/recommendations` APIs. Missing measurements are shown as
unavailable. Use the optional reader/admin API tokens above for controlled
access; tokens are shared credentials and do not provide per-user identity.

Run profile tests and the existing project checks with the documented isolated
test-copy procedure above. The focused profile tests are
`backend/tests/test_profiling.py`; frontend transformations are covered by
`npm test` from `frontend`, followed by `npm run build`.

The in-process deduplication lock and SSE fanout assume the
default single Uvicorn worker; multiple workers would need shared coordination.
Keep the API bound to a trusted local environment. Ingestion requires a
minimum 32-byte shared bearer token. Optional read/admin bearer tokens protect
the broader API, including event, alert, and stream reads. The application has
no user accounts or per-organization authorization. Do not expose it to
untrusted networks without TLS and appropriate secret management.

## Behavioral fingerprint contract

The existing operational `BehavioralFingerprint` remains fingerprint v1 and
continues to drive adaptation and bundle generation. A separate adapter in
`backend/app/intelligence/fingerprint_schema.py` exposes the contract
`decentralized_honeypot.behavioral_fingerprint`, schema version 1. The adapter
does not change existing strategy thresholds or fingerprint fields. It
validates a bounded, typed view and rejects unknown schema versions instead of
reinterpreting them. Legacy v1 API records without `schema_name` and
`schema_version` are accepted only when `fingerprint_version` is 1.

Stable v1 operational features are:

| Feature | Type and meaning |
| --- | --- |
| `event_count` | Non-negative interaction count, max 100,000. |
| `unique_decoys_accessed`, `unique_actions` | Non-negative counts bounded by `event_count`. |
| `action_sequence` | Ordered observed actions; length equals `event_count`. |
| `action_frequencies` | Counts by observed action; absent/empty legacy maps derive from the verified action sequence. |
| `decoy_types_accessed` | Unique observed category labels. |
| `decoy_type_frequencies` | Observed category counts; an empty legacy map stays unavailable instead of being inferred from unique categories. |
| `credential_probing`, `database_probing`, `file_probing`, `repeated_access` | Validated boolean indicators derived by the existing extractor. |
| `first_seen`, `last_seen` | Internal timestamps; optional in validated representations. |
| `timing_reliable` | True only when timestamps are comparable and the span is positive. |
| `elapsed_seconds`, `interactions_per_minute` | Finite numeric timing features only when reliable; otherwise null. |
| `risk_score`, `risk_level` | Existing 0–100 deterministic heuristic score and low/medium/high category. |
| `reasons`, `assessment_type` | Internal explanatory text and the fixed heuristic-baseline label. |

The compatibility adapter preserves fingerprint v1 semantics. Missing action
counts are derived from `action_sequence`; missing decoy-category counts remain
unknown. Unsupported versions, inconsistent counts, contradictory probing
flags, invalid ranges, non-finite values, and invalid timing combinations are
rejected. Comparable timestamps with an invalid order are also rejected.

### Canonical shareable export

`GET /api/v1/intelligence/fingerprints/{actor_id}/export` returns an explicit
allowlist: schema name/version, event and unique counts, fixed action and decoy
category count maps, probing/repeated indicators, timing reliability and
coarsened timing bands, and the existing heuristic risk category. Unknown
categories are trimmed, lowercased, then aggregated into a fixed `other`
bucket. The export excludes actor IDs, sequences, raw timestamps, event/decoy
IDs, reasons, payloads, and paths. A legacy missing decoy-frequency map is
zero-filled only with `decoy_type_frequencies_available: false`.

Canonical JSON uses UTF-8-safe compact JSON, lexically sorted object keys,
explicit null values, and standard JSON booleans/numbers. It contains no export
timestamp. The accompanying SHA-256 is computed over those canonical UTF-8
bytes and is an integrity/content identifier only; it is not anonymization.

Example internal v1 fingerprint (normally returned by the existing fingerprint
endpoint):

```json
{
  "fingerprint_version": 1,
  "actor_id": "synthetic-actor-001",
  "event_count": 1,
  "unique_decoys_accessed": 1,
  "unique_actions": 1,
  "action_sequence": ["read"],
  "action_frequencies": {"read": 1},
  "decoy_types_accessed": ["file"],
  "decoy_type_frequencies": {"file": 1},
  "credential_probing": false,
  "database_probing": false,
  "file_probing": true,
  "repeated_access": false,
  "elapsed_seconds": null,
  "interactions_per_minute": null,
  "timing_reliable": false,
  "first_seen": "2026-01-01T00:00:00Z",
  "last_seen": "2026-01-01T00:00:00Z",
  "risk_score": 0,
  "risk_level": "low",
  "reasons": ["No additional heuristic risk indicators observed"],
  "assessment_type": "heuristic_baseline"
}
```

Its shareable export contains the same aggregate counts and booleans, but no
`actor_id`, timestamps, sequence, or reason text. Its vector has the fixed
26-value order below; this example vector is for the one-event `read` case
above:

```json
{
  "schema_name": "decentralized_honeypot.behavioral_fingerprint",
  "schema_version": 1,
  "event_count": 1,
  "unique_decoys_accessed": 1,
  "unique_actions": 1,
  "action_frequencies": {
    "view": 0, "read": 1, "attempt_login": 0, "query": 0, "other": 0
  },
  "decoy_type_frequencies": {
    "file": 1, "credential": 0, "database_record": 0, "other": 0
  },
  "decoy_type_frequencies_available": true,
  "credential_probing": false,
  "database_probing": false,
  "file_probing": true,
  "repeated_access": false,
  "timing_reliable": false,
  "elapsed_time_band": null,
  "interaction_rate_band": null,
  "risk_level": "low"
}
```

```json
{
  "schema_name": "decentralized_honeypot.behavioral_vector",
  "schema_version": 1,
  "fingerprint_schema_name": "decentralized_honeypot.behavioral_fingerprint",
  "fingerprint_schema_version": 1,
  "feature_order": [
    "event_count", "unique_decoys_accessed", "unique_actions",
    "action_frequency.view", "action_frequency.read",
    "action_frequency.attempt_login", "action_frequency.query",
    "action_frequency.other", "decoy_type_frequencies_available",
    "decoy_frequency.file", "decoy_frequency.credential",
    "decoy_frequency.database_record", "decoy_frequency.other",
    "credential_probing", "database_probing", "file_probing",
    "repeated_access", "timing_reliable", "elapsed_seconds.value",
    "elapsed_seconds.missing", "interactions_per_minute.value",
    "interactions_per_minute.missing", "risk_score", "risk_level.low",
    "risk_level.medium", "risk_level.high"
  ],
  "values": [1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0]
}
```

Every vector value is a finite float. Boolean indicators use 0/1; risk level is
one-hot; action and decoy frequencies use fixed category dimensions with an
`other` bucket. Null timing uses value 0 paired with a missing-indicator value
of 1. Missing legacy decoy frequencies use zero counts and an explicit
availability value of 0. The vector is an input adapter for future
scikit-learn-compatible models, not a trained model and not evidence of better
detection accuracy.

### Fingerprint endpoints

```text
GET  /api/v1/intelligence/fingerprints/schema
POST /api/v1/intelligence/fingerprints/validate
GET  /api/v1/intelligence/fingerprints/{actor_id}/export
GET  /api/v1/intelligence/fingerprints/{actor_id}/vector
```

The schema endpoint returns feature definitions, fixed vector order, missing
and unknown-category rules, and the compatibility policy. The validation body
is an operational fingerprint object; a legacy object from
`GET /api/v1/intelligence/fingerprints/{actor_id}` is accepted as v1 without
adding schema metadata. Successful validation returns only validity and schema
metadata; malformed input returns HTTP 422 with sanitized field errors. The
export and vector endpoints return derived representations and do not persist
or alter history, bundles, events, or the ledger. Actor-specific paths follow
existing API conventions; configure optional reader/admin API tokens for
access control. Actor paths may still appear in HTTP access logs.

Removing direct identifiers does not make an export anonymous. Rare action
combinations, event counts, risk categories, and coarse timing buckets can
still be linkable with outside information. Share only under an appropriate
data-sharing agreement and review each organization's privacy requirements.

## Technology Stack

- Python
- FastAPI
- scikit-learn
- Deterministic behavior-conditioned policy
- React and Vite
- Reinforcement learning (future research)
- Permissioned blockchain (planned)

## Signed strategy sharing (Phase 4)

Strategy-sharing record schema is `decentralized_honeypot.strategy_share`,
version 1. Version 1 is strict: unknown fields and unsupported versions are
rejected; later incompatible formats require a new schema version. Records
contain a simulated organization ID, strategy, the existing allowlisted
fingerprint aggregate and its digest, a sanitized bundle-template projection
(asset/relationship categories only) and its digest, a canonical record
digest (`SHA-256`), key ID, timestamp, and Ed25519 signature. They do not include actor,
event, scenario, decoy, or bundle IDs; raw events; free-text rationale; asset
content; credentials; or private keys. A digest provides integrity checking,
not anonymity or confidentiality.

The signature uses the domain prefix
`decentralized-honeypot:strategy-sharing:v1\0`; this is separate from ledger
checkpoint signing. Configure a dedicated Ed25519 PKCS#8 private key path with
`HONEYPOT_STRATEGY_SHARING_PRIVATE_KEY_PATH`, its simulated issuer with
`HONEYPOT_STRATEGY_SHARING_ORGANIZATION_ID`, and its key ID with
`HONEYPOT_STRATEGY_SHARING_KEY_ID`. The verifier trust map is explicitly
configured in `HONEYPOT_STRATEGY_SHARING_TRUSTED_KEYS` as JSON mapping key IDs
to `organization_id` and PEM `public_key`. Imported records cannot add keys to
this map, and the checkpoint key is never used as an organization identity.
Do not configure a signing key for an organization unless its public key is
also provisioned in the explicit trust map. The organization name is an
operator mapping from key ID to a simulated label; it is not proof of a real
publisher identity. There is no automated key rotation or revocation protocol.
Update the trust configuration and restart the process to change trust.
Pending and evaluated records are rechecked against the current configured key
at activation; already active approval records are not automatically revoked.

API workflow:

```text
POST /api/v1/strategy-sharing/exports/{actor_id}
POST /api/v1/strategy-sharing/imports
GET  /api/v1/strategy-sharing/imports/{record_id}
POST /api/v1/strategy-sharing/imports/{record_id}/evaluate
POST /api/v1/strategy-sharing/imports/{record_id}/activate
```

After configuring the dedicated signer and trust map, PowerShell can export,
import, evaluate, and activate a package as follows (the actor identifier is
used only to select local source data; it is not included in the returned
record):

```powershell
$record = Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/exports/demo-actor-001"
$imported = Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/imports" `
  -ContentType "application/json" `
  -Body ($record | ConvertTo-Json -Depth 20)
$recordId = $imported.record_id
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/imports/$recordId/evaluate"
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/strategy-sharing/imports/$recordId/activate"
```

Export creates only the sanitized signed record. Import verifies strict schema,
fingerprint and template digests, template consistency, trusted organization
key, and signature before storing it as `pending`. Evaluation runs the
existing five-scenario evaluation service with isolated temporary SQLite
databases and records its actual summary. It passes only if all requested
scenario runs complete and the imported strategy appears in measured strategy
selections. A failed or incomplete evaluation cannot be activated. Activation
is a separate audited approval state; it does not replace or override the
existing local deterministic strategy-selection policy.

Duplicate imports of the same record ID are rejected by the local primary key.
Replay detection is local to this SQLite store; there is no shared replay
registry or freshness window across installations. Configure reader/admin API
tokens and TLS before exposing these routes to an untrusted network. There is
no per-user or organization identity. The export route takes an actor ID in
its URL, which may be present in HTTP access logs even though it is excluded
from the signed record.
Evaluation responses expose aggregate metrics only; detailed per-run records
remain in the local sharing database.

This implementation uses simulated organization IDs for repeatable local
testing. There is no authenticated organization identity, remote transport,
or consensus layer. The registry is a local SQLite record store, not a
decentralized blockchain. API tokens do not establish organization identity;
deployment still requires appropriate identity and transport controls.

### In-process organization replication demonstration

`backend/app/strategy_replication.py` provides `SimulatedOrganizationNode` for
an in-process two-node demonstration. Each node has a separate SQLite path and
its own Ed25519 private key. Operators explicitly provision each peer's public
key in the receiver's trust map. The sender exports the signed record as a
JSON-compatible dictionary; the receiver verifies it through the existing
strategy-sharing service, stores it as pending, evaluates it locally, and
requires a separate approval call. A node without the sender key and a
modified transfer payload are rejected. Duplicate record IDs return HTTP 409
without replacing the first import. Private keys are held by their source node
and are not part of the transfer payload.

This is a local simulation of independent participants. It does not provide
remote transport, authenticated organization identity, consensus, shared
replay detection, high availability, or Byzantine fault tolerance. The
demonstration is reproducible with the test-only generated keys and temporary
SQLite stores in this command (run it from a source-only temporary copy as in
the test instructions below):

```powershell
python -m pytest -q backend/tests/test_strategy_sharing.py::test_two_organization_replication_and_untrusted_third_node
```

The full suite and focused replication test must run from a fresh source-only
temporary copy because importing the app can initialize local SQLite stores
and the checkpoint key. Use the exclusion-aware PowerShell procedure in
[docs/TESTING.md](docs/TESTING.md); it omits backup files, databases, signing
keys, virtual environments, and build output.

Verification snapshot from an isolated source copy on 2026-10-22: focused
strategy-sharing/replication tests, **13 passed, 1 warning**; complete backend
suite, **141 passed, 1 warning**. The warning is Starlette's deprecation notice
about using `httpx` with `TestClient`. Test timing varies by machine.

### HTTP multi-node threat-intelligence prototype

`backend/app/network/replication.py` adds an optional standalone node app
factory. Nodes use separately configured SQLite stores, Ed25519 keys, explicit
trusted-public-key maps, and peer-specific bearer tokens. They exchange bounded
`honeypot.threat-intel.v1` indicator records over HTTP; imports verify the
publisher mapping, bearer token, SHA-256 digest, timestamp window, and
domain-separated Ed25519 signature before durable pending storage. Duplicate
record delivery is idempotent and reports its existing state; record ID reuse
with changed content is rejected. Peer enablement, health timestamps, failures,
and sync attempts persist per node. The receiver supports explicit approve or
reject decisions with local audit records. This is an actual HTTP exchange API; the older
`SimulatedOrganizationNode` section above remains an in-process strategy-sharing
demonstration.

Run the full live-process walkthrough from PowerShell with:

```powershell
$repoRoot = (Get-Location).Path
$env:PYTHONPATH = "$(Join-Path $repoRoot 'backend');$repoRoot"
& (Join-Path $repoRoot ".venv/Scripts/python.exe") -m app.network.live_demo `
  --data-dir (Join-Path $env:TEMP ("honeypot-live-demo-" + [guid]::NewGuid().ToString("N")))
```

The runner generates separate test-only keys/configs/databases, starts two
Uvicorn processes on localhost, transfers a signed record, checks duplicate
and tamper behavior, stops/restarts Node B, and verifies synchronization after
restart. The complete config and individual API commands are in
[`docs/NODE_REPLICATION.md`](docs/NODE_REPLICATION.md).

Event-to-intelligence collection is a separate opt-in policy. It requires
configured source/event mappings, a severity floor, and repeated sightings;
it accepts a bounded event projection, rejects private/reserved IPs by
default, and never blocks or enforces indicators. Imports expire after 30 days,
retain publisher/source provenance, and remain pending until operator review.
Duplicate and conflicting indicators are linked for review. A disclosed
observation-count heuristic is shown as a confidence score, not a probability.

Peer identities are configured statically; there is no automatic discovery.
Publisher replacement keys are staged with an out-of-band SHA-256 fingerprint,
explicitly activated, and explicitly revoked. Revocation marks records signed
by that key as revoked. Local signing-key rotation uses a new key ID/private-key
file and a node restart against its existing node database; every receiver must
independently stage and activate the new public key. See
[`docs/NODE_REPLICATION.md`](docs/NODE_REPLICATION.md) for commands.

The dashboard signs in using the backend session flow above. Node dashboard
data is proxied by the backend using `HONEYPOT_NODE_DASHBOARD_URL` and
`HONEYPOT_NODE_DASHBOARD_TOKEN`; no node token or API reader token is configured
in Vite. Existing baseline/adaptive performance comparisons use the synthetic
experiment harness below.

The focused network tests include both ASGI-level cases and an actual two
Uvicorn-process localhost integration:

```powershell
python -m pytest backend/tests/test_network_replication.py -q
```

The prototype authenticates possession of operator-configured node keys; it
does not prove a legal organization identity. It does not implement consensus,
automatic peer discovery, TLS deployment automation, a remote key lifecycle
service, high availability, or automatic threat enforcement. Publish only vetted
indicators and keep node APIs on trusted networks behind TLS and appropriate
access controls.

## Manual dashboard verification (2026-11-26)

The operator manually verified the dashboard from the original project
directory. Three controlled SSH sessions generated **15 genuine Cowrie
records**; ingestion reported **15 accepted, zero errors, and zero
duplicates**. Administrator login, logout, and re-login succeeded. Telemetry
and Cowrie activity rendered with 3 successful emulated logins, 6 session
events, 0 failed logins, and 0 command attempts.

Profile recomputation produced one 15-observation profile classified as
Authentication Probing (mean anomaly index 0.438, cluster 4) using
`attacker-profile-synthetic-v1`. One deception recommendation passed local
synthetic evaluation (8/8 interactions, 10 synthetic decoys, 678.5 ms) and was
approved. Approval is recorded workflow state only; it does not deploy decoys
or enforce a policy. The model is trained on synthetic data, and these results
do not establish real-world detection or defense effectiveness.

The populated alerts and incidents panels were not visually verified, and the
optional node dashboard was unconfigured. The sidebar text “Simulation mode /
Synthetic activity only” is misleading when real sensor telemetry is also
shown; the wording remains unchanged. The complete startup, restricted
temporary-token-file handling, and cleanup steps are in
[`docs/FINAL_DEMO_GUIDE.md`](docs/FINAL_DEMO_GUIDE.md).

## Milestone 8: offline adversary experiments

`backend/app/simulation/adversary.py` and `backend/app/experiments/` implement
ten deterministic, offline synthetic adversary scenarios and paired baseline,
adaptive, and optional closed-loop experiments. The engine reuses the existing versioned
behavior feature extractor, synthetic-trained classifier, recommendation
policy, and incident correlator. Existing adaptive recommendations change only
experiment-local detection thresholds. Optional `closed_loop` mode adds a
deterministic contextual epsilon-greedy strategy policy, seeded synthetic
attacker reactions, follow-up synthetic interaction records, measured reward,
and per-experiment bounded policy updates. Baseline/adaptive comparisons also
record engagement under the same seeded synthetic reaction model while keeping
detector measurements paired on the same initial event set. Results include
simulated engagement, event-count interaction depth, and virtual event-time
duration. Unique decoys accessed is explicitly unavailable because scenario
events do not identify decoy assets. The reaction probabilities and reward
weights are explicit assumptions, not learned from real attackers; these
measurements are not observed attacker dwell or real deception effectiveness.
Scenario data, incident state, and
experiment summaries use separate temporary/dedicated stores; the existing
operational event ledger, decoy registry, and live policy are not changed.

The API can launch an experiment at `POST /api/v1/experiments/run`, list
summaries at `GET /api/v1/experiments`, retrieve a run at
`GET /api/v1/experiments/{experiment_id}`, retrieve its scenario results and
comparison at `/results` and `/comparison`, and download stored reports at
`/report?format=json|csv|markdown`. `HONEYPOT_EXPERIMENT_DB_PATH` selects the
separate experiment SQLite database (default `data/experiments.sqlite3`). The
dashboard includes scenario/mode selection, seed and repetition controls,
aggregate comparisons, adaptation reasons, simulated reactions and rewards,
saved experiments, and report links. Existing clients still default to the
two established modes; include `"closed_loop"` explicitly in `modes` to run
the new feedback simulation. Detailed metric formulas, API examples, safety boundaries, and
limitations are in [docs/EXPERIMENTAL_EVALUATION.md](docs/EXPERIMENTAL_EVALUATION.md).

Verification snapshot from an isolated source copy on 2026-11-07: backend
suite **274 passed, 1 warning**; frontend tests **8 passed**; production build
completed. The warning is Starlette's `TestClient` deprecation notice for
httpx. These are local synthetic workflow checks, not evidence of real-world
defense effectiveness.

All labels and events are generated locally. The model prediction is kept
separate from ground truth. Incident rates use the existing configured
correlator; event-level TP/FP/FN use the harness's bounded threshold detector.
Capture describes local processing only and is expected to be 100% when all
generated records are processed. These synthetic results do not show
real-world operational effectiveness. Confidence intervals and peak memory
are unavailable. Run the focused checks with `python -m pytest
backend/tests/test_experiments.py -q`; run frontend checks from `frontend/` with
`npm test` and `npm run build`. Use the isolated source-copy backend test
procedure above to avoid touching local application state.

Milestone 8 verification run on 2026-11-07 used temporary source/test copies
and temporary experiment/incident SQLite files: focused experiment tests,
**10 passed, 1 warning**; complete backend suite, **266 passed, 1 warning**;
frontend tests, **8 passed**; production build succeeded. The backend warning
is Starlette's deprecation notice for `httpx` with `TestClient`. The frontend
build output was directed to a temporary folder. These are synthetic software
checks, not operational-performance evidence.

Final local regression check on 2026-11-14 used fresh source copies and
temporary test databases/keys: focused security, Zeek, Cowrie, and profiling
tests plus simulation failure handling, **71 passed, 1 warning**; complete backend suite, **284 passed, 1
warning**; frontend tests, **8 passed**; production build succeeded with
output directed to `%TEMP%`. The warning is Starlette's deprecation notice
about `httpx` use with `TestClient`. These checks validate local code paths,
not sensor deployment or real-world defense effectiveness.
