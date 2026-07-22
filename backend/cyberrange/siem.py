"""SIEM forwarding seam.

When enabled (WAZUH_INGEST_ENABLED=1), every timeline event is also written as
a JSON line to a shared log file that a real Wazuh manager tails (log_format
json). Wazuh decodes the JSON, its rules raise alerts, and the alert-forwarder
(deploy/wazuh/forwarder) posts those real alerts back to CyberRange as
detections. This is the ingestion half of the telemetry-broker seam; it is a
no-op unless explicitly enabled, so the default SQLite/local experience is
unchanged.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


class EventSink:
    """Append events as JSON lines to the Wazuh ingest file."""

    def __init__(self, path: str | None = None, enabled: bool | None = None):
        self.enabled = _truthy(os.environ.get("WAZUH_INGEST_ENABLED")) \
            if enabled is None else enabled
        self.path = path or os.environ.get(
            "WAZUH_INGEST_PATH", "/var/log/cyberrange/events.json")
        self._lock = threading.Lock()
        if self.enabled:
            try:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.enabled = False

    def write(self, event: dict) -> None:
        if not self.enabled:
            return
        # SIEM forwarding must never break an exercise - swallow I/O errors.
        try:
            line = json.dumps({"cyberrange": True, **event}, default=str)
            with self._lock, open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except (OSError, TypeError):
            pass
