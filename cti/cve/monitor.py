"""
Delta Monitor — Track and fetch new/updated CVEs from cvelistV5 delta.json.

State is managed via the unified state system (app.cve_state).
"""

import requests

DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"


class DeltaMonitor:
    """Monitor delta.json for new/updated CVEs.

    Uses an in-memory state dict (managed externally by the unified state system).
    """

    def __init__(self, state: dict):
        """Initialize with a reference to the shared CVE state dict."""
        self._state = state

    def fetch_delta(self) -> dict | None:
        """Fetch current delta.json from GitHub."""
        try:
            resp = requests.get(DELTA_URL, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"[CVE] [ERR] Failed to fetch delta.json: {e}")
            return None

    def fetch_delta_log(self) -> list | None:
        """Fetch deltaLog.json for catchup after downtime."""
        try:
            print("[CVE] [INFO] Fetching deltaLog.json for catchup...")
            resp = requests.get(DELTA_LOG_URL, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"[CVE] [ERR] Failed to fetch deltaLog.json: {e}")
            return None

    def get_new_entries(self, delta: dict) -> tuple[list[dict], list[dict]]:
        """
        Compare delta against saved state.
        Returns (new_cves, updated_cves) — each is a list of delta entry dicts.
        """
        fetch_time = delta.get("fetchTime", "")

        # Already processed this exact snapshot
        if fetch_time == self._state.get("last_fetch_time"):
            return [], []

        new_entries = delta.get("new", [])
        updated_entries = delta.get("updated", [])

        # Filter out already-processed CVE IDs (dedup for catchup scenarios)
        processed = set(self._state.get("processed_cves", []))
        new_entries = [e for e in new_entries if e.get("cveId") not in processed]

        return new_entries, updated_entries

    def mark_processed(self, fetch_time: str, cve_ids: list[str]):
        """Mark a delta snapshot as processed (in-memory only, caller must persist)."""
        self._state["last_fetch_time"] = fetch_time
        # Keep last 500 processed CVEs to avoid deduplication issues
        existing = self._state.get("processed_cves", [])
        existing.extend(cve_ids)
        self._state["processed_cves"] = existing[-500:]

    def catchup(self) -> list[dict]:
        """
        On first run or after downtime, process missed deltas from deltaLog.json.
        Returns list of delta snapshots to process (oldest first).
        """
        last_time = self._state.get("last_fetch_time")
        if last_time is None:
            print("[CVE] [INFO] First run — processing only the latest delta")
            return []

        delta_log = self.fetch_delta_log()
        if not delta_log:
            return []

        # deltaLog is newest-first; filter entries newer than last_fetch_time
        missed = []
        for entry in delta_log:
            ft = entry.get("fetchTime", "")
            if ft > last_time:
                missed.append(entry)
            else:
                break  # Already processed and older

        missed.reverse()  # Process oldest first
        print(f"[CVE] [INFO] Catchup: {len(missed)} missed delta snapshots since {last_time}")
        return missed

    def fetch_cve_json(self, github_link: str) -> dict | None:
        """Download full CVE JSON from GitHub raw link."""
        try:
            resp = requests.get(github_link, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"[CVE] [ERR] Failed to fetch CVE JSON from {github_link}: {e}")
            return None
