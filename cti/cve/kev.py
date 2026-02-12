"""
CISA KEV Lookup — Download and cache Known Exploited Vulnerabilities catalog.
"""

import json
import time
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
            # Check TTL
            mtime = self._cache_file.stat().st_mtime
            age_hours = (time.time() - mtime) / 3600
            if age_hours < self._cache_ttl_hours:
                print(f"[CVE] [INFO] Loading KEV catalog from cache ({self._cache_file.name})")
                try:
                    with open(self._cache_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self._process_catalog(data)
                        return
                except Exception:
                    pass  # Fallback to download

        print("[CVE] [INFO] Downloading CISA KEV catalog...")
        try:
            resp = requests.get(KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            self._cache_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            self._process_catalog(data)
            print(f"[CVE] [INFO] KEV catalog loaded: {len(self._catalog)} entries")
        except Exception as e:
            print(f"[CVE] [WARN] Failed to load KEV catalog: {e}")

    def _process_catalog(self, data: dict):
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                self._catalog[cve_id] = vuln

    def lookup(self, cve_id: str) -> dict | None:
        """Return KEV entry for the given CVE ID, or None."""
        if not self._enabled:
            return None
        return self._catalog.get(cve_id)
