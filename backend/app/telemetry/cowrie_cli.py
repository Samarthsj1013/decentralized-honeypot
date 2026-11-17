"""Incrementally forward Cowrie JSON logs to one explicitly configured API."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.telemetry.cowrie import MAX_COWRIE_LINE_BYTES, CowrieRecordError, parse_cowrie_record


@dataclass
class CowrieRunSummary:
    dry_run: bool = False
    records_read: int = 0
    accepted: int = 0
    duplicates: int = 0
    event_type_counts: Counter = field(default_factory=Counter)
    failed_offset: int | None = None
    error: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _validated_api_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("API URL must be an explicit HTTP(S) base URL without user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("API URL must be a base origin, without path, query, or fragment")
    return value.rstrip("/")


def _file_prefix(path: Path, length: int) -> str:
    with path.open("rb") as handle:
        return hashlib.sha256(handle.read(length)).hexdigest()


def _save_cursor(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _post_event(api_url: str, token: str, event) -> bool:
    request = urllib.request.Request(
        api_url + "/api/v1/telemetry/ingest",
        data=event.model_dump_json().encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status == 201:
                return False
            if response.status == 200:
                try:
                    payload = json.loads(response.read(4096).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    payload = None
                if isinstance(payload, dict) and payload.get("duplicate") is True:
                    return True
            raise RuntimeError(f"telemetry API returned unexpected HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"telemetry API rejected the event (HTTP {exc.code}); cursor was not advanced") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach the configured telemetry API ({type(exc.reason).__name__}); cursor was not advanced") from None


def process_file(
    log_path: Path,
    *,
    api_url: str,
    sensor_id: str,
    token: str | None,
    cursor_path: Path,
    dry_run: bool = False,
    post_event=_post_event,
) -> CowrieRunSummary:
    api_url = _validated_api_url(api_url)
    if not sensor_id or len(sensor_id) > 64 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for char in sensor_id):
        raise ValueError("sensor ID must contain 1 to 64 characters")
    if not dry_run and (token is None or len(token.encode("utf-8")) < 32):
        raise ValueError("a telemetry bearer token of at least 32 bytes is required")

    resolved = log_path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("Cowrie log path must be a regular file")
    file_size = resolved.stat().st_size
    cursor: dict[str, Any] = {
        "version": 1, "path": str(resolved), "api_url": api_url,
        "sensor_id": sensor_id, "offset": 0,
    }
    if cursor_path.exists():
        try:
            stored = json.loads(cursor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise ValueError("cursor file is unreadable; inspect it before continuing") from None
        if not isinstance(stored, dict) or any(stored.get(key) != cursor[key] for key in ("version", "path", "api_url", "sensor_id")):
            raise ValueError("cursor does not match this log, API, or sensor; inspect log rotation before resetting it")
        prefix_length = stored.get("prefix_length")
        if type(prefix_length) is not int or not 0 <= prefix_length <= 4096 or file_size < prefix_length:
            raise ValueError("log identity changed or log was truncated; inspect rotation and use a new cursor")
        cursor["prefix_length"] = prefix_length
        cursor["prefix_sha256"] = _file_prefix(resolved, prefix_length)
        if stored.get("prefix_sha256") != cursor["prefix_sha256"]:
            raise ValueError("log identity changed; inspect rotation and use a new cursor")
        cursor.update(stored)
    else:
        cursor["prefix_length"] = min(file_size, 4096)
        cursor["prefix_sha256"] = _file_prefix(resolved, cursor["prefix_length"])
    offset = cursor.get("offset")
    if type(offset) is not int or offset < 0 or offset > file_size:
        raise ValueError("log is shorter than its saved cursor or the cursor offset is invalid; use a new cursor after verifying rotation")

    summary = CowrieRunSummary(dry_run=dry_run)
    with resolved.open("rb") as handle:
        handle.seek(offset)
        while True:
            record_offset = handle.tell()
            raw = handle.readline(MAX_COWRIE_LINE_BYTES + 2)
            if not raw:
                break
            if len(raw) > MAX_COWRIE_LINE_BYTES + 1 or (len(raw) == MAX_COWRIE_LINE_BYTES + 1 and not raw.endswith(b"\n")):
                summary.failed_offset = record_offset
                summary.error = "Cowrie record exceeds the maximum line size"
                break
            if not raw.endswith(b"\n"):
                # The producer may still be writing the final JSON object.
                break
            next_offset = handle.tell()
            if not raw.strip():
                if not dry_run:
                    cursor["offset"] = next_offset
                    _save_cursor(cursor_path, cursor)
                continue
            try:
                event = parse_cowrie_record(raw.rstrip(b"\r\n"), sensor_id=sensor_id)
            except CowrieRecordError as exc:
                summary.failed_offset = record_offset
                summary.error = str(exc)
                break
            summary.records_read += 1
            summary.event_type_counts[event.event_type] += 1
            if dry_run:
                continue
            try:
                duplicate = post_event(api_url, token or "", event)
            except Exception as exc:
                summary.failed_offset = record_offset
                summary.error = str(exc)
                break
            if duplicate:
                summary.duplicates += 1
            else:
                summary.accepted += 1
            cursor["offset"] = next_offset
            _save_cursor(cursor_path, cursor)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safely ingest Cowrie JSON logs into the configured telemetry API")
    parser.add_argument("--log-file", type=Path, required=True)
    parser.add_argument("--api-url", required=True, help="Explicit telemetry API base origin")
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--token-env", default="HONEYPOT_TELEMETRY_INGEST_TOKEN", help="Environment variable containing the bearer token")
    parser.add_argument("--cursor-file", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    token = os.getenv(args.token_env) if args.token_env else None
    try:
        summary = process_file(
            args.log_file, api_url=args.api_url, sensor_id=args.sensor_id,
            token=token, cursor_path=args.cursor_file, dry_run=args.dry_run,
        )
    except Exception as exc:
        print(f"Cowrie ingestion stopped: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "dry_run": summary.dry_run,
        "records_read": summary.records_read,
        "accepted": summary.accepted,
        "duplicates": summary.duplicates,
        "event_type_counts": dict(sorted(summary.event_type_counts.items())),
        "failed_offset": summary.failed_offset,
        "error": summary.error,
    }, sort_keys=True))
    return 1 if summary.error else 0


if __name__ == "__main__":
    raise SystemExit(main())
