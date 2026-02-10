"""
CISA KEV Lookup — Download and cache Known Exploited Vulnerabilities catalog.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVLookup:
    """Download and cache CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, enabled: bool = True, cache_file: str = "data/cve_kev_cache.json",
                 cache_ttl_hours: int = 24):
        self._catalog: dict[str, dict] = {}
        self._enabled = enabled
        self._cache_file = Path(cache_file)
        self._cache_ttl_hours = cache_ttl_hours
        if enabled:
            self._load()

    def _load(self):
        """Load KEV catalog from cache or download fresh."""
        if self._cache_file.exists():
            age = datetime.now(timezone.utc) - datetime.fromtimestamp(
                self._cache_file.stat().st_mtime, tz=timezone.utc
            )
            if age < timedelta(hours=self._cache_ttl_hours):
                print(f"[CVE Monitor] Loading KEV catalog from cache ({self._cache_file.name})")
                data = json.loads(self._cache_file.read_text(encoding="utf-8"))
                self._index(data)
                return

        print("[CVE Monitor] Downloading CISA KEV catalog...")
        try:
            resp = requests.get(KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            self._cache_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            self._index(data)
            print(f"[CVE Monitor] KEV catalog loaded: {len(self._catalog)} entries")
        except Exception as e:
            print(f"[WARN] Failed to load KEV catalog: {e}")

    def _index(self, data: dict):
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                self._catalog[cve_id] = vuln

    def lookup(self, cve_id: str) -> dict | None:
        """Return KEV entry for the given CVE ID, or None."""
        if not self._enabled:
            return None
        return self._catalog.get(cve_id)
