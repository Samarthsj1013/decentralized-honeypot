"""Incrementally forward Suricata EVE JSON records to the configured API."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.events.models import TelemetryIngestRequest
from app.telemetry.suricata import MAX_EVE_LINE_BYTES, SuricataRecordError, parse_eve_record


@dataclass
class SuricataRunSummary:
    records_read: int = 0
    accepted: int = 0
    duplicates: int = 0
    alert_events: int = 0
    dry_run: bool = False
    error: str | None = None
    failed_offset: int | None = None
    event_types: dict[str, int] = field(default_factory=dict)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward the configured bearer credential to a redirect target.
        return None


def _save_cursor(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _post_event(api_url: str, token: str, event: TelemetryIngestRequest) -> bool:
    request = urllib.request.Request(
        api_url.rstrip("/") + "/api/v1/telemetry/ingest",
        data=event.model_dump_json().encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status not in {200, 201}:
                raise RuntimeError(f"telemetry API returned HTTP {response.status}")
            return response.status == 201
    except urllib.error.HTTPError as exc:
        # Do not print a response body; it may reflect untrusted event content.
        raise RuntimeError(f"telemetry API rejected event (HTTP {exc.code})") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach configured telemetry API: {exc.reason}") from None


def _initial_cursor(log_path: Path, api_url: str, sensor_id: str) -> dict[str, Any]:
    return {
        "version": 1,
        "path": str(log_path.resolve()),
        "api_url": api_url.rstrip("/"),
        "sensor_id": sensor_id,
        "offset": 0,
    }


def process_file(
    log_path: Path,
    *,
    api_url: str,
    token: str | None,
    sensor_id: str,
    cursor_path: Path,
    dry_run: bool = False,
) -> SuricataRunSummary:
    """Process complete EVE lines, checkpointing only accepted/duplicate events.

    A malformed record or API failure stops processing at that record. The
    source line is not copied to errors/logs and the cursor is left before it,
    so the operator can inspect/fix the original log and safely retry.
    """
    resolved = log_path.resolve()
    cursor = _initial_cursor(resolved, api_url, sensor_id)
    if cursor_path.exists():
        try:
            stored = json.loads(cursor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise ValueError("cursor file is unreadable; inspect it before continuing") from None
        if (
            not isinstance(stored, dict)
            or stored.get("version") != 1
            or stored.get("path") != cursor["path"]
            or stored.get("api_url") != cursor["api_url"]
            or stored.get("sensor_id") != sensor_id
        ):
            raise ValueError("cursor belongs to a different log file, API, or sensor")
        cursor.update(stored)
    try:
        offset = int(cursor["offset"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("cursor offset is invalid") from None
    if offset < 0 or offset > resolved.stat().st_size:
        raise ValueError("log is shorter than the saved cursor; use a new cursor for a rotated or truncated file")

    summary = SuricataRunSummary(dry_run=dry_run)
    with resolved.open("rb") as handle:
        handle.seek(offset)
        while True:
            line_offset = handle.tell()
            raw = handle.readline(MAX_EVE_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_EVE_LINE_BYTES:
                summary.error = f"record at byte {line_offset} exceeds the maximum line size"
                summary.failed_offset = line_offset
                break
            if not raw.endswith(b"\n"):
                # A live producer may still be writing the final JSON object.
                # Leave it unread and retry from this byte on the next run.
                break
            record_bytes = raw.rstrip(b"\r\n")
            try:
                event = parse_eve_record(record_bytes, sensor_id=sensor_id)
            except (SuricataRecordError, ValueError) as exc:
                summary.error = f"malformed EVE record at byte {line_offset}: {exc}"
                summary.failed_offset = line_offset
                break

            summary.records_read += 1
            event_type = event.attributes.get("event_type", "unknown")
            summary.event_types[event_type] = summary.event_types.get(event_type, 0) + 1
            summary.alert_events += int(event_type == "alert")
            if dry_run:
                continue
            if not token:
                summary.error = "a bearer token is required unless --dry-run is used"
                summary.failed_offset = line_offset
                break
            try:
                created = _post_event(api_url, token, event)
            except (RuntimeError, urllib.error.URLError) as exc:
                summary.error = f"transmission failed at byte {line_offset}: {exc}"
                summary.failed_offset = line_offset
                break
            if created:
                summary.accepted += 1
            else:
                summary.duplicates += 1
            cursor["offset"] = handle.tell()
            _save_cursor(cursor_path, cursor)
    return summary


def _validate_api_url(value: str) -> bool:
    parsed = urlparse(value)
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", required=True, type=Path)
    parser.add_argument("--api-url", required=True, help="Explicit telemetry API base URL")
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--token-env", required=True, help="Environment variable containing the bearer token")
    parser.add_argument("--cursor-file", type=Path, help="Restart cursor; defaults beside the EVE log")
    parser.add_argument("--dry-run", action="store_true", help="Parse and summarize without transmitting or checkpointing")
    args = parser.parse_args(argv)
    if not _validate_api_url(args.api_url):
        parser.error("--api-url must be an explicit http(s) URL without user info, query, or fragment")
    token = os.environ.get(args.token_env)
    if not args.dry_run and not token:
        parser.error(f"environment variable {args.token_env!r} is not set")
    cursor = args.cursor_file or args.log_file.with_name(args.log_file.name + ".cursor.json")
    try:
        summary = process_file(
            args.log_file,
            api_url=args.api_url,
            token=token,
            sensor_id=args.sensor_id,
            cursor_path=cursor,
            dry_run=args.dry_run,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Suricata ingestion stopped: {exc}", file=sys.stderr)
        return 1
    label = "Dry-run records" if args.dry_run else "Records processed"
    print(
        f"{label}: {summary.records_read}; accepted: {summary.accepted}; "
        f"duplicates: {summary.duplicates}; alert events: {summary.alert_events}; "
        f"event types: {json.dumps(summary.event_types, sort_keys=True)}"
    )
    if summary.error is not None:
        print(f"Suricata ingestion stopped: {summary.error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
