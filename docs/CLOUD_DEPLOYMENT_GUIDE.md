# Placement Demonstration Cloud Deployment

This guide deploys the public, read-only Version 1.0 placement demonstration.
The `deployment-v1` branch runs a small FastAPI app dedicated to the public
snapshot. It does not load the operator API, create checkpoint keys, accept
telemetry, run simulations, mutate recommendations, or load/train ML models.

The required dashboard banner is **Placement Demonstration — Synthetic
Security Data**. Telemetry, alerts, and incidents are deterministic synthetic
fixtures. The aggregate profile and local evaluation figures are reproduced
from the previously operator-verified controlled Cowrie lab run using
invented credentials and emulated sessions. No raw logs, credentials, actual
attacker identities, or local database are included. Model predictions and
synthetic test results are not evidence of real-world detection performance.

No external Vercel or Render service has been created by this change. Free
tiers only are selected in the example. Do not enable a paid plan or persistent
disk without separate approval.

## What the public backend permits

The Render entry point is `app.public_demo:app`, not `app.main:app`. It has no
admin session router or operator tokens. The backend only serves `GET
/healthz` and `GET /api/v1/public-demo`. Other paths, including `/docs`,
authentication, event and fingerprint reads, ledger reads, telemetry
ingestion, profile recomputation, simulation, sharing, approval, and peer
operations, return 404. Non-GET methods are rejected. This policy also applies
when a client calls the Render origin directly. If a supplied browser `Origin`
is not in the exact CORS origin configuration, the request is rejected.

The response is validated against a strict schema that has no fields for actor
or event IDs, IP addresses, credentials, raw events, fingerprints, keys, or
database IDs. The database contains only one checksummed public snapshot row.
Startup inserts the deterministic seed when missing, verifies it on every
start, and never appends duplicate rows. A corrupt or unavailable store makes
readiness fail and the public snapshot returns 503.

## Render setup

1. In Render, authorize the GitHub repository and create a **Web Service**.
2. Choose the `deployment-v1` branch. Use the repository root as the service
   root directory; the start command uses `--app-dir backend`.
3. Select the **Free** instance. Do not attach a persistent disk or create a
   database.
4. Set the following commands (also represented in `render.yaml`):

   ```text
   Build: pip install -r backend/requirements-demo.txt
   Start: python -m uvicorn app.public_demo:app --app-dir backend --host 0.0.0.0 --port $PORT
   Health check path: /healthz
   ```

5. Set these environment variables in Render:

   | Name | Value |
   | --- | --- |
   | `PYTHON_VERSION` | `3.12.8` |
   | `HONEYPOT_ENV` | `production` |
   | `HONEYPOT_DEMO_DB_PATH` | `/tmp/honeypot-placement-demo/demo.sqlite3` |
   | `HONEYPOT_CORS_ORIGINS` | The exact HTTPS Vercel production origin, e.g. `https://<your-project>.vercel.app` |

   The CORS origin value is required and must not contain a wildcard, path,
   credentials, or query string. It is safe to set after Vercel assigns the
   production URL. This demo does not need `HONEYPOT_API_ADMIN_TOKEN`,
   `HONEYPOT_API_READ_TOKEN`, telemetry tokens, private keys, or an ML model.
6. After the first deploy, copy the actual Render service URL from the
   dashboard. Do not assume a service URL based on its display name.

Render Free services use ephemeral filesystems. The demo database is at `/tmp`
and the fixture is reseeded after a cold restart, restart, or redeploy. Visitor
requests cannot write to it. Free services sleep after 15 minutes without
traffic and may take about a minute to wake. Current Render documentation also
lists 750 free instance-hours per workspace each month and no persistent disks
for Free services. Free PostgreSQL instances expire after 30 days, so this
demo does not use one. See [Render Free services](https://render.com/docs/free)
and [Render pricing](https://render.com/pricing).

## Vercel setup

1. In Vercel, import the GitHub repository and select branch `deployment-v1`.
2. Set the project root directory to `frontend`.
3. Configure the Vite build:

   ```text
   Install command: npm ci
   Build command: npm run build
   Output directory: dist
   ```

4. Add these project environment variables for Production:

   ```text
   VITE_API_BASE_URL=/api/v1
   VITE_PUBLIC_DEMO=true
   ```

   These are public UI settings, not credentials. Never put an API token,
   administrative token, or private key in a `VITE_` variable.
5. Open `frontend/vercel.json` and replace
   `https://REPLACE-WITH-RENDER-SERVICE.onrender.com` with the actual HTTPS
   service origin copied from Render. Keep the `/api/:path*` mapping. Commit
   and push deployment changes only after reviewing and approving them.
6. Deploy Vercel after Render is healthy. Relative API calls use Vercel's
   same-origin external rewrite, so browser JavaScript does not receive a
   backend token or contact a hard-coded localhost API. Verify the rewrite
   behavior with the tests below and the Vercel production URL. Vercel
   documents external rewrites as reverse proxies that preserve the browser
   URL: [Vercel rewrites](https://vercel.com/docs/routing/rewrites).

The Vercel Hobby plan is free and limited to personal/non-commercial use under
Vercel's current plan terms. Confirm that your intended placement portfolio
usage fits before selecting it. This guide does not enable a paid plan. See
[Hobby plan](https://vercel.com/docs/plans/hobby) and
[Vercel terms](https://vercel.com/legal/terms).

## Local checks before publishing

From the repository root, use the backend virtual environment and a database
path outside the checkout:

```powershell
$env:PYTHONPATH = "$PWD\backend;$PWD"
$env:HONEYPOT_ENV = 'production'
$env:HONEYPOT_DEMO_DB_PATH = (Join-Path $env:TEMP 'honeypot-placement-demo-test\demo.sqlite3')
$env:HONEYPOT_CORS_ORIGINS = 'https://placement-demo.example'
& .\.venv\Scripts\python.exe -m pytest backend/tests/test_public_demo.py -q --basetemp (Join-Path $env:TEMP 'honeypot-placement-tests') -p no:cacheprovider

Set-Location frontend
npm.cmd test
npm.cmd run build
```

The full backend suite should be run from a fresh source-only copy with
temporary database paths. Follow [`TESTING.md`](../TESTING.md); do not point a
test at local `data/`, `backend/data/`, or key files.

## Deployment verification

After deployment, check the Render URL directly and the Vercel proxied route:

```text
GET https://<actual-render-origin>/healthz                         -> 200
GET https://<actual-render-origin>/api/v1/public-demo              -> 200
GET https://<actual-vercel-origin>/api/v1/public-demo              -> 200
GET https://<actual-render-origin>/api/v1/events                    -> 404
GET https://<actual-render-origin>/docs                             -> 404
POST https://<actual-render-origin>/api/v1/telemetry/ingest         -> 404
POST https://<actual-render-origin>/api/v1/auth/session             -> 404
```

The public response should show the exact synthetic-data label, bounded
telemetry examples, Cowrie-style summaries, synthetic alerts/incidents, one
precomputed aggregate profile, and reviewed recommendation examples. It must
not contain IP addresses, event/actor IDs, credentials, raw telemetry, tokens,
private keys, or operational database rows. Direct Render access and the
Vercel rewrite must enforce the same path/method allowlist. Confirm that browser
network tools show only the relative `/api/v1/public-demo` request and no
admin credential or login prompt.

Vercel's external rewrites are not cached by default. Keep them uncached unless
the response caching policy is explicitly reviewed. The static dashboard can
render the previous snapshot only while the request is active; when Render is
asleep or unavailable, the UI displays a retry message.

## Troubleshooting

- **Render fails to start:** verify the repository root, Python 3.12.8,
  minimal demo requirements, Uvicorn start command, and Render's `PORT` value.
- **Render health is 503:** inspect service logs and confirm
  `HONEYPOT_DEMO_DB_PATH` is writable and outside the project checkout. A
  damaged snapshot intentionally fails closed; deleting a database is not a
  troubleshooting step. Use the disposable `/tmp` path so restart reseeds it.
- **Origin rejected:** set `HONEYPOT_CORS_ORIGINS` to the exact HTTPS Vercel
  production origin, without a trailing path. Preview domains need their own
  explicit origin if you intend to use them.
- **Proxy returns 502/404:** make sure the Vercel rewrite target is the exact
  Render origin and preserves `/api/:path*`; redeploy after changing it.
- **Dashboard shows unavailable:** the Render Free service may be waking.
  Retry after about a minute and inspect `/healthz`.
- **Vercel plan question:** confirm Hobby eligibility for your usage before
  enabling the project; choose no paid upgrade without explicit approval.

## Rollback

Use the Render and Vercel dashboards to roll back to the last known-good
deployment for this demo branch. If the branch is not yet pushed, no cloud
service can deploy it; review, commit, and push only after the implementation
report is approved. The released `main` branch and `v1.0.0` tag remain
unchanged. No local operational database or key is part of the rollback path.

## Limits

- The dashboard snapshot is fixed and read-only. It does not ingest live
  Cowrie, Zeek, or Suricata events and displays no active alerts from a running
  sensor.
- Synthetic events, alert rules, and incidents are examples. The profile is an
  aggregate from the controlled local Cowrie demonstration and uses a model
  trained on synthetic labels. The evaluation is a previously verified local
  synthetic workflow result. These values are not evidence of real-world
  effectiveness.
- The public Render service has no connected nodes. The codebase supports a
  signed exchange prototype; this deployment does not run peer replication,
  consensus, or enforcement.
- Render Free is ephemeral, sleeps while idle, and has a constrained memory
  allocation. The public runtime avoids importing NumPy, scikit-learn,
  pandas, and joblib. An isolated local Windows Uvicorn process reached its
  first healthy response in about 2.5 seconds. The sandbox's process-memory
  readings were implausibly low, so memory was not reliably measured. Render
  service memory and cold-start behavior remain unverified until a real preview
  deploy.
