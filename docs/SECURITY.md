# Security model and deployment notes

## Trust boundaries

- Telemetry is untrusted data. Parsers bound record sizes and project selected
  fields. The backend does not execute commands, payloads, or uploaded files.
- Telemetry ingestion requires its own bearer token of at least 32 bytes.
  Other `/api/v1` routes use optional shared reader/admin tokens. With neither
  token configured, development mode is open. Set `HONEYPOT_ENV=production`
  and configure tokens before any non-loopback exposure.
- Reader and admin tokens must be different values. A misconfigured short or
  identical pair fails closed. The admin token can read and mutate; the reader
  can only use safe methods. These shared credentials do not identify users.
- Credentialed CORS permits only configured exact HTTP(S) origins; wildcard
  origins, paths, user info, queries and fragments are rejected. CORS is not
  authentication. Use TLS and a managed access-control layer outside the local
  prototype.
- The dashboard exchanges the operator-entered admin token for a 30-minute
  server-side session. Its cookie is `HttpOnly`, `SameSite=Strict`, scoped to
  `/api/v1`; mutating requests require a CSRF header token. Login is origin
  checked against configured CORS origins, limits login JSON to 1 KiB, and
  throttles five failed attempts per source IP over 15 minutes in process-local
  state.
  Logout invalidates the server-side session. The session store is per process;
  restart invalidates sessions, and it is not shared across workers.
- Development mode with neither API token configured remains explicitly open
  for compatibility and is labeled in the UI; the login screen is skipped.
  Production must configure tokens and cannot use this open-mode path.
- Production must set `HONEYPOT_SESSION_COOKIE_SECURE=true` and use HTTPS.
  Local HTTP mode leaves `Secure` off, so bind the UI and API under the same
  loopback hostname (`127.0.0.1` or `localhost`). The admin bearer token is
  entered at runtime and is not included in Vite build variables or browser
  storage. It is still present in page memory during sign-in.
- The optional node operations panel obtains node data through the backend
  endpoint `/api/v1/network-node/dashboard`. Configure
  `HONEYPOT_NODE_DASHBOARD_URL` and `HONEYPOT_NODE_DASHBOARD_TOKEN` only in the
  backend process. The proxy uses a fixed summary path, short timeout, no
  redirects, and a response-size limit. Never expose either value through a
  `VITE_` variable.
- Session role is administrator; existing bearer roles remain administrator
  and read-only reader. There are no individual accounts, MFA, identity
  provider, per-user audit, persistent session store, or distributed login
  throttling. This is safer local browser handling, not a production IAM
  substitute.
- Node publisher keys are trusted only when provisioned in the node's local
  registry. Replacement keys begin pending and require explicit activation
  after an out-of-band SHA-256 fingerprint comparison. Revocation is an
  explicit, irreversible local-admin action and causes records from that key
  to be marked revoked. This is not automated key distribution, and publisher
  key possession is not proof of organizational/legal identity.
- Strategy-sharing keys use a separate application trust map. That subsystem
  still has no staged key-rotation or revocation API; update its trusted-key
  configuration out of band and restart the application. It does not reuse
  node keys or the ledger checkpoint key.
- Node-local key rotation requires generating a new key out of band, changing
  the private-key path and key ID in that node's configuration, and restarting
  it against the same node database. Receivers must stage and activate the new
  public key separately. Old key material is never sent to peers; local public
  key history is retained for historical signature verification.
- Configure exact dashboard CORS origins; CORS is not authentication. Node
  dashboard credentials stay in the backend proxy configuration.
- The ledger checkpoint key is local and generated/loaded by application
  initialization. Protect its file separately; do not reuse it as a strategy
  publisher identity. A local signature does not provide an independent
  timestamp or remote witness.
- SQLite stores are local files. Use restrictive filesystem permissions,
  backups, and tested recovery procedures. Tests that import application
  modules can initialize SQLite and a checkpoint key; use the temporary-copy
  procedure in [Testing](TESTING.md).
- `joblib.load` deserializes Python model artifacts. Model files must come only
  from a trusted operator-controlled source and must not be uploaded or
  replaced by untrusted users.

## Known controls and gaps

Implemented controls include bounded telemetry bodies/JSON, strict telemetry
envelopes, deterministic external-event deduplication, parameterized SQL,
separate SQLite stores, safe event projections for live updates, signed and
validated strategy records, and a local hash-chain integrity check. The
Zeek/Suricata/Cowrie file clients send only to their explicitly configured
collector and refuse redirects to prevent credential forwarding. Interaction
generation failures return a stable generic API message rather than raw
exception text that could reveal local storage details.

The application has no per-user accounts, persistent or distributed session
store, distributed login throttling, centralized secret manager, automated
distributed trust/revocation, or production-grade multi-tenant isolation. Do
not expose it directly to the public internet. Use an authenticated reverse
proxy, TLS, strict network isolation, resource limits, monitoring, and an
operational incident-response process for any controlled lab deployment. The
included Cowrie Compose configuration binds to loopback by default and uses an
internal network; do not casually change that exposure.

## Data handling

Cowrie usernames are replaced at ingestion with deterministic SHA-256
references salted by the configured sensor ID; this prevents the raw username
from appearing in event/ledger API payloads but is pseudonymization, not
anonymization, and common names may be guessed. Raw Cowrie source logs may
contain passwords and commands; keep them access-restricted and outside Git.
Suricata templates omit packet payloads and strip HTTP query/fragment values.
Shared strategy records omit actor/event identifiers, raw events and free-text
rationale.

Node intelligence is an indicator claim, not verified ground truth. Imports
are time-bounded to 30 days, retain publisher/key/source provenance, remain
pending until an operator approves or rejects them, and write local audit
events. The displayed confidence score is a disclosed heuristic of the signed
aggregate observation count only. Duplicate and classification-conflicting
indicators are retained and linked for review. No intelligence action blocks
traffic or automatically changes deception policy.
