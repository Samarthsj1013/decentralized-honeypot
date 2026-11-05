"""Incrementally forward a Zeek conn.log to the configured telemetry API."""

from __future__ import annotations

import argparse
import codecs
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.events.models import TelemetryIngestRequest
from app.telemetry.zeek_conn import iter_zeek_tsv, parse_json_record


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
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status not in {200, 201}:
                raise RuntimeError(f"telemetry API returned HTTP {response.status}")
            return response.status == 201
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            body = json.loads(exc.read(4096).decode("utf-8"))
            detail = str(body.get("detail", "")) if isinstance(body, dict) else ""
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        raise RuntimeError(f"telemetry API rejected event (HTTP {exc.code}): {detail}") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"could not reach configured telemetry API: {exc.reason}") from None


def process_file(
    log_path: Path, *, api_url: str, token: str, sensor_id: str, cursor_path: Path
) -> tuple[int, int]:
    """Forward new records and persist a restart-safe byte cursor."""
    resolved = log_path.resolve()
    cursor: dict[str, Any] = {
        "path": str(resolved), "api_url": api_url.rstrip("/"),
        "sensor_id": sensor_id, "offset": 0, "format": None,
        "fields": None, "types": None, "separator": "\t",
        "unset_field": "-", "empty_field": "(empty)",
    }
    if cursor_path.exists():
        try:
            stored = json.loads(cursor_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise ValueError("cursor file is unreadable; inspect it before continuing") from None
        if (
            not isinstance(stored, dict)
            or stored.get("path") != str(resolved)
            or stored.get("api_url") != api_url.rstrip("/")
            or stored.get("sensor_id") != sensor_id
        ):
            raise ValueError("cursor belongs to a different log file, API, or sensor")
        cursor.update(stored)
    sent = duplicates = 0
    with resolved.open("r", encoding="utf-8", errors="strict", newline="") as handle:
        if int(cursor["offset"]) > resolved.stat().st_size:
            raise ValueError("log file is shorter than its saved cursor; use a new cursor for rotated logs")
        handle.seek(int(cursor["offset"]))
        while True:
            line_start = handle.tell()
            line = handle.readline()
            if not line:
                break
            line_end = handle.tell()
            if not line.endswith(("\n", "\r")):
                # The producer may still be writing this record. Retry it on
                # the next invocation instead of advancing beyond the tail.
                break
            stripped = line.rstrip("\r\n")
            if not stripped:
                cursor["offset"] = line_end
                _save_cursor(cursor_path, cursor)
                continue
            if cursor["format"] is None:
                cursor["format"] = "json" if stripped.lstrip().startswith("{") else "tsv"
            if cursor["format"] == "json":
                event = parse_json_record(stripped, sensor_id=sensor_id)
            elif stripped.startswith("#separator "):
                cursor["separator"] = codecs.decode(stripped[len("#separator "):], "unicode_escape")
                if len(cursor["separator"]) != 1:
                    raise ValueError("Zeek separator must decode to exactly one character")
                cursor["offset"] = line_end
                _save_cursor(cursor_path, cursor)
                continue
            elif stripped.startswith("#fields"):
                cursor["fields"] = stripped.split(cursor["separator"])[1:]
                cursor["offset"] = line_end
                _save_cursor(cursor_path, cursor)
                continue
            elif stripped.startswith("#types"):
                cursor["types"] = stripped.split(cursor["separator"])[1:]
                cursor["offset"] = line_end
                _save_cursor(cursor_path, cursor)
                continue
            elif stripped.startswith("#unset_field"):
                cursor["unset_field"] = stripped.split(cursor["separator"], 1)[1]
                cursor["offset"] = line_end
                _save_cursor(cursor_path, cursor)
                continue
            elif stripped.startswith("#empty_field"):
                cursor["empty_field"] = stripped.split(cursor["separator"], 1)[1]
                cursor["offset"] = line_end
                _save_cursor(cursor_path, cursor)
                continue
            elif stripped.startswith("#"):
                cursor["offset"] = line_end
                _save_cursor(cursor_path, cursor)
                continue
            else:
                parsed = list(
                    iter_zeek_tsv(
                        [line],
                        sensor_id=sensor_id,
                        fields=cursor["fields"],
                        types=cursor["types"],
                        separator=cursor["separator"],
                        unset_field=cursor["unset_field"],
                        empty_field=cursor["empty_field"],
                    )
                )
                if len(parsed) != 1:
                    raise ValueError(f"could not parse Zeek record at byte {line_start}")
                event = parsed[0]
            created = _post_event(api_url, token, event)
            sent += int(created)
            duplicates += int(not created)
            cursor["offset"] = line_end
            _save_cursor(cursor_path, cursor)
    return sent, duplicates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", required=True, type=Path)
    parser.add_argument("--api-url", required=True, help="Base URL of the telemetry API")
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--token-env", required=True, help="Environment variable holding the bearer token")
    parser.add_argument("--cursor-file", type=Path, help="Restart cursor (defaults beside the log)")
    args = parser.parse_args(argv)
    parsed_url = urlparse(args.api_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        parser.error("--api-url must be an explicit http:// or https:// URL")
    token = os.environ.get(args.token_env)
    if not token:
        parser.error(f"environment variable {args.token_env!r} is not set")
    cursor = args.cursor_file or args.log_file.with_name(args.log_file.name + ".cursor.json")
    try:
        sent, duplicates = process_file(
            args.log_file, api_url=args.api_url, token=token,
            sensor_id=args.sensor_id, cursor_path=cursor,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Zeek ingestion failed: {exc}", file=sys.stderr)
        return 1
    print(f"New events accepted: {sent}; confirmed duplicates: {duplicates}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
