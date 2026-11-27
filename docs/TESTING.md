# Testing and isolated verification

Backend application imports can initialize local ledger SQLite storage and a
checkpoint signing key. Do not run the full suite from the working checkout
when it may contain local data. Make a fresh source copy and exclude all
database files, key files, backups, virtual environments, caches, and build
output. The older ML endpoint test also needs the trusted local
`experiments/results/behavior_model.joblib` artifact; copy that artifact only
if it exists. It is not a database or private key.

## Full backend suite (PowerShell)

Run from the project root. The commands leave the repository untouched and
create test stores under `$env:TEMP`:

```powershell
$repoRoot = (Get-Location).Path
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$tempRoot = Join-Path $env:TEMP ("honeypot-backend-" + [guid]::NewGuid().ToString("N"))
$pytestTemp = Join-Path $env:TEMP ("honeypot-pytest-" + [guid]::NewGuid().ToString("N"))
$appTemp = Join-Path $oldTemp ("honeypot-app-temp-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot, $pytestTemp, $appTemp -Force | Out-Null
foreach ($sourceRoot in @("backend/app", "backend/tests")) {
  $sourcePath = Join-Path $repoRoot $sourceRoot
  Get-ChildItem -LiteralPath $sourcePath -Recurse -File |
    Where-Object {
      $_.Name -notmatch '(\.bak\d*$|backup|~$)' -and
      $_.Extension -notin @(".sqlite", ".sqlite3", ".db", ".pem", ".key", ".joblib", ".pyc")
    } |
    ForEach-Object {
      $relative = $_.FullName.Substring($sourcePath.TrimEnd('\').Length).TrimStart('\')
      $destination = Join-Path (Join-Path $tempRoot $sourceRoot) $relative
      New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
      Copy-Item -LiteralPath $_.FullName -Destination $destination
    }
}
Copy-Item (Join-Path $repoRoot "backend/requirements.txt") (Join-Path $tempRoot "backend/requirements.txt")
if (Test-Path (Join-Path $repoRoot "experiments/results/behavior_model.joblib")) {
  New-Item -ItemType Directory -Path (Join-Path $tempRoot "experiments/results") -Force | Out-Null
  Copy-Item (Join-Path $repoRoot "experiments/results/behavior_model.joblib") (Join-Path $tempRoot "experiments/results/behavior_model.joblib")
}
$env:PYTHONPATH = "$(Join-Path $tempRoot 'backend');$tempRoot"
$env:TEMP = $appTemp
$env:TMP = $appTemp
Push-Location $tempRoot
try {
  & (Join-Path $repoRoot ".venv/Scripts/python.exe") -m pytest backend/tests -q --rootdir=$tempRoot --basetemp=$pytestTemp -p no:cacheprovider
} finally {
  Pop-Location
  $env:TEMP = $oldTemp
  $env:TMP = $oldTmp
}
```

The separate app temp path is intentional: the public-demo path-policy test
must compare pytest's `tmp_path` with a different configured temp root to
exercise rejection of a path outside that root. Both locations remain under
the Windows temporary directory and outside the project checkout.

Use `-v` instead of `-q` for test names. A test that needs the old model
artifact will fail if that ignored artifact is absent; do not fabricate a
replacement model merely to make the suite pass.

## Frontend checks

These checks do not import the backend or touch application storage:

```powershell
Set-Location frontend
npm.cmd test
npm.cmd run build -- --outDir (Join-Path $env:TEMP ("honeypot-vite-" + [guid]::NewGuid().ToString("N")))
```

## Whitespace and source review

From the repository root:

```powershell
git diff --check
git status --short
```

Test counts and timing depend on the current tree, Python/dependency versions,
and presence of the local classifier artifact. Report only output from the
specific run performed; historical README snapshots are not current test
results.
