# Decentralized AI Honeypot dashboard

This is the first frontend in the repository; React and Vite were listed as planned in the project README.

## Start

```powershell
Set-Location D:\Desktop\decentralized-honeypot\decentralized-honeypot\frontend
npm.cmd install
npm.cmd run dev
```

Start the FastAPI service separately from the repository root:

```powershell
Set-Location D:\Desktop\decentralized-honeypot\decentralized-honeypot
$env:PYTHONPATH = "$PWD\backend;$PWD"
python -m uvicorn app.main:app --reload --app-dir backend
```

The dashboard defaults to `http://127.0.0.1:8000/api/v1`. Set `VITE_API_BASE_URL` in a local `.env` file to use a different API URL, then restart Vite.

The browser origin `http://127.0.0.1:5173` or `http://localhost:5173` is allowed by the backend's configurable `HONEYPOT_CORS_ORIGINS` setting. Set that variable to a comma-separated origin list when hosting the UI elsewhere. Credentials are not enabled for CORS.

Run the UI checks with `npm.cmd test` and create a production bundle with `npm.cmd run build`.
