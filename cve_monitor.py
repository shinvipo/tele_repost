#!/usr/bin/env python3
"""
CVE Monitor — Telegram Alert Bot
Monitors cvelistV5 delta.json for new/updated CVEs and sends formatted Telegram alerts.

Usage:
    python cve_monitor.py --bot-token TOKEN --chat-id CHAT_ID [--interval 300]
    python cve_monitor.py --dry-run          # Print messages to console, no Telegram
    python cve_monitor.py --once             # Process current delta once and exit

Environment variables (alternative to CLI):
    CVE_BOT_TOKEN, CVE_CHAT_ID, CVE_POLL_INTERVAL
"""

import argparse
import html
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SCRIPT_DIR = Path(__file__).resolve().parent
STATE_FILE = SCRIPT_DIR / "last_fetch.json"
KEV_CACHE_FILE = SCRIPT_DIR / "kev_cache.json"
KEV_CACHE_TTL_HOURS = 24

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
TELEGRAM_MAX_LEN = 4096

DEFAULT_POLL_INTERVAL = 300  # 5 minutes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cve_monitor")


# ===========================================================================
# CISA KEV Lookup
# ===========================================================================

class KEVLookup:
    """Download and cache CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self, enabled: bool = True):
        self._catalog: dict[str, dict] = {}
        self._enabled = enabled
        if enabled:
            self._load()

    def _load(self):
        """Load KEV catalog from cache or download fresh."""
        if KEV_CACHE_FILE.exists():
            age = datetime.now(timezone.utc) - datetime.fromtimestamp(
                KEV_CACHE_FILE.stat().st_mtime, tz=timezone.utc
            )
            if age < timedelta(hours=KEV_CACHE_TTL_HOURS):
                log.info("Loading KEV catalog from cache (%s)", KEV_CACHE_FILE.name)
                data = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
                self._index(data)
                return

        log.info("Downloading CISA KEV catalog...")
        try:
            resp = requests.get(KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            KEV_CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            self._index(data)
            log.info("KEV catalog loaded: %d entries", len(self._catalog))
        except Exception as e:
            log.warning("Failed to load KEV catalog: %s", e)

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


# ===========================================================================
# CVE Parser
# ===========================================================================

class CVEParser:
    """Parse a cvelistV5 JSON record into a normalized dict."""

    def parse(self, raw: dict) -> dict:
        """Parse raw CVE JSON into normalized structure."""
        metadata = raw.get("cveMetadata", {})
        cna = raw.get("containers", {}).get("cna", {})
        adp_list = raw.get("containers", {}).get("adp", [])

        # Find CISA-ADP entry
        cisa_adp = self._find_cisa_adp(adp_list)

        # CVSS: CNA first, then ADP fallback
        cvss = self._extract_cvss(cna.get("metrics", []))
        if cvss["score"] is None and cisa_adp:
            cvss = self._extract_cvss(cisa_adp.get("metrics", []))

        # Weaknesses: CNA first, then ADP fallback
        weaknesses = self._extract_weaknesses(cna.get("problemTypes", []))
        if not weaknesses and cisa_adp:
            weaknesses = self._extract_weaknesses(cisa_adp.get("problemTypes", []))

        # Affected products
        affected = self._extract_affected(cna.get("affected", []))

        # Description (prefer English plain text)
        description = self._extract_description(cna.get("descriptions", []))

        # References from CNA
        references = self._extract_references(cna.get("references", []))

        # POC / Exploit detection
        poc = self._extract_poc(cna, adp_list)

        # CISA SSVC from ADP
        ssvc = self._extract_ssvc(cisa_adp) if cisa_adp else None

        return {
            "cve_id": metadata.get("cveId", "UNKNOWN"),
            "title": cna.get("title", ""),
            "description": description,
            "cvss_score": cvss["score"],
            "cvss_vector": cvss["vector"],
            "cvss_version": cvss["version"],
            "cvss_severity": cvss["severity"],
            "scope": cvss["scope"],
            "affected_products": affected,
            "weaknesses": weaknesses if weaknesses else ["unknown"],
            "published_date": metadata.get("datePublished", ""),
            "last_modified_date": metadata.get("dateUpdated", ""),
            "references": references,
            "cisa_ssvc": ssvc,
            "poc_exploit": poc,
            "assigner": metadata.get("assignerShortName", ""),
        }

    # --- CVSS ---

    def _extract_cvss(self, metrics: list) -> dict:
        """Extract CVSS with priority: v3.1 > v3.0 > v4.0 > v2.0."""
        result = {"score": None, "vector": None, "version": None, "severity": None, "scope": None}
        priorities = [
            ("cvssV3_1", "3.1"),
            ("cvssV3_0", "3.0"),
            ("cvssV4_0", "4.0"),
            ("cvssV2_0", "2.0"),
        ]
        for metric_entry in metrics:
            for key, ver in priorities:
                if key in metric_entry:
                    cvss_obj = metric_entry[key]
                    result["score"] = cvss_obj.get("baseScore")
                    result["vector"] = cvss_obj.get("vectorString", "")
                    result["version"] = ver
                    result["severity"] = cvss_obj.get("baseSeverity", "")
                    result["scope"] = cvss_obj.get("scope", "")
                    return result
        return result

    # --- Weaknesses / CWE ---

    def _extract_weaknesses(self, problem_types: list) -> list[str]:
        """Extract CWE entries from problemTypes."""
        results = []
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                cwe_desc = desc.get("description", "")
                if cwe_id:
                    # Normalize: "CWE-89: description" or just "CWE-89"
                    if cwe_desc and cwe_id not in cwe_desc:
                        results.append(f"{cwe_id}: {cwe_desc}")
                    elif cwe_desc:
                        results.append(cwe_desc)
                    else:
                        results.append(cwe_id)
                elif cwe_desc:
                    # Freetext CWE (e.g., Oracle)
                    results.append(cwe_desc)
        return results

    # --- Affected products & versions ---

    def _extract_affected(self, affected_list: list) -> list[dict]:
        """Extract and normalize affected products and versions."""
        results = []
        for entry in affected_list:
            vendor = entry.get("vendor", "unknown")
            product = entry.get("product", "unknown")
            package = entry.get("packageName", "")
            default_status = entry.get("defaultStatus", "")

            versions = []
            for ver in entry.get("versions", []):
                versions.append(self._normalize_version(ver))

            # No versions array but defaultStatus = affected → all versions affected
            if not versions and default_status == "affected":
                versions.append({"type": "all", "display": "Tất cả phiên bản (chưa có bản vá)", "raw": {}})

            # Deduplicate git_range entries (e.g., 7 identical "Git commits" lines)
            git_count = sum(1 for v in versions if v.get("type") == "git_range")
            if git_count > 1:
                versions = [v for v in versions if v.get("type") != "git_range"]
                versions.insert(0, {"type": "git_range", "display": "Git commits (xem references)", "raw": {}})

            results.append({
                "vendor": vendor,
                "product": product,
                "package_name": package,
                "versions": versions,
            })
        return results

    def _normalize_version(self, ver: dict) -> dict:
        """Normalize a single version entry to {type, display}."""
        version_val = ver.get("version", "")
        less_than = ver.get("lessThan", "")
        less_than_or_equal = ver.get("lessThanOrEqual", "")
        status = ver.get("status", "")
        version_type = ver.get("versionType", "")

        # Unaffected entries → fixed version
        if status == "unaffected":
            fixed_ver = version_val
            # lessThan: "*" means "all versions from this point onwards are unaffected"
            if less_than == "*" or less_than_or_equal == "*":
                if fixed_ver in ("", "0", "*", "n/a"):
                    # version "0" + lessThan "*" + unaffected = not affected at all
                    return {"type": "not_affected", "display": "Không bị ảnh hưởng", "raw": ver}
                else:
                    return {"type": "fixed", "display": f"Đã sửa trong {fixed_ver}+", "raw": ver}
            # Specific lessThan with version "0" = "versions before X are not affected"
            if less_than and fixed_ver in ("", "0", "*", "n/a"):
                return {"type": "not_affected", "display": f"Không bị ảnh hưởng (trước {less_than})", "raw": ver}
            return {"type": "fixed", "display": f"Đã sửa trong {fixed_ver}", "raw": ver}

        # Git commit ranges — not human-friendly
        if version_type == "git":
            return {"type": "git_range", "display": "Git commits (xem references)", "raw": ver}

        # Clean embedded operators from lessThanOrEqual (e.g., "<= 1.4.0")
        if less_than_or_equal:
            less_than_or_equal = re.sub(r"^[<>=\s]+", "", less_than_or_equal)

        if less_than:
            less_than_clean = re.sub(r"^[<>=\s]+", "", less_than)

        # Complex range string in version: ">= 9.0.0, < 9.6.33"
        if re.match(r"[><=]", version_val) and "," in version_val:
            # Parse ">= X, < Y" pattern
            parts = [p.strip() for p in version_val.split(",")]
            display = self._range_parts_to_display(parts)
            return {"type": "range", "display": display, "raw": ver}

        # Simple "< X" or "<= X" in version field
        if version_val.startswith("<"):
            cleaned = re.sub(r"^[<>=\s]+", "", version_val)
            op = "<=" if "<=" in version_val else "<"
            if op == "<=":
                return {"type": "range", "display": f"Từ đầu đến {cleaned}", "raw": ver}
            else:
                return {"type": "range", "display": f"Phiên bản trước {cleaned}", "raw": ver}

        # lessThan present
        if less_than:
            start = version_val if version_val not in ("*", "n/a", "0", "") else ""
            if start and start != "0":
                return {"type": "range", "display": f"Từ {start} đến trước {less_than_clean}", "raw": ver}
            else:
                return {"type": "range", "display": f"Phiên bản trước {less_than_clean}", "raw": ver}

        # lessThanOrEqual present
        if less_than_or_equal:
            start = version_val if version_val not in ("*", "n/a", "0", "") else ""
            if start and start != "0":
                return {"type": "range", "display": f"Từ {start} đến {less_than_or_equal}", "raw": ver}
            else:
                return {"type": "range", "display": f"Từ đầu đến {less_than_or_equal}", "raw": ver}

        # Exact version
        if version_val and version_val not in ("*", "n/a", "0"):
            return {"type": "exact", "display": f"Chính xác: {version_val}", "raw": ver}

        # Wildcard "*" with affected status = all versions
        if version_val == "*" and status == "affected":
            return {"type": "all", "display": "Tất cả phiên bản", "raw": ver}

        return {"type": "unknown", "display": "Chưa xác định", "raw": ver}

    def _range_parts_to_display(self, parts: list[str]) -> str:
        """Convert range parts like ['>= 9.0.0', '< 9.6.33'] to display string."""
        start = end = ""
        for p in parts:
            p = p.strip()
            if p.startswith(">="):
                start = re.sub(r"^>=\s*", "", p)
            elif p.startswith(">"):
                start = re.sub(r"^>\s*", "", p) + " (exclusive)"
            elif p.startswith("<="):
                end = re.sub(r"^<=\s*", "", p)
            elif p.startswith("<"):
                end = "trước " + re.sub(r"^<\s*", "", p)

        if start and end:
            return f"Từ {start} đến {end}"
        elif start:
            return f"Từ {start} trở lên"
        elif end:
            return f"Đến {end}"
        return ", ".join(parts)

    # --- Description ---

    def _extract_description(self, descriptions: list) -> str:
        """Extract English plain-text description."""
        for desc in descriptions:
            lang = desc.get("lang", "")
            if lang.startswith("en"):
                return desc.get("value", "")
        # Fallback: first available
        if descriptions:
            return descriptions[0].get("value", "")
        return ""

    # --- References ---

    def _extract_references(self, refs: list) -> list[dict]:
        """Extract reference URLs with tags."""
        results = []
        for ref in refs:
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            name = ref.get("name", "")
            if url:
                results.append({"url": url, "tags": tags, "name": name})
        return results

    # --- POC / Exploit ---

    def _extract_poc(self, cna: dict, adp_list: list) -> dict:
        """Detect POC/exploit from CNA references, ADP references, and SSVC."""
        sources = []
        has_poc = False

        # Check CNA references for 'exploit' tag
        for ref in cna.get("references", []):
            if "exploit" in ref.get("tags", []):
                has_poc = True
                sources.append(ref.get("url", ""))

        # Check ADP references for 'exploit' tag
        for adp in adp_list:
            for ref in adp.get("references", []):
                if "exploit" in ref.get("tags", []):
                    has_poc = True
                    url = ref.get("url", "")
                    if url not in sources:
                        sources.append(url)

            # Check SSVC Exploitation field
            for metric in adp.get("metrics", []):
                other = metric.get("other", {})
                if other.get("type") == "ssvc":
                    options = other.get("content", {}).get("options", [])
                    for opt in options:
                        exploit_val = opt.get("Exploitation", "")
                        if exploit_val in ("poc", "active"):
                            has_poc = True

        return {"has_poc": has_poc, "sources": sources}

    # --- SSVC ---

    def _extract_ssvc(self, cisa_adp: dict) -> dict | None:
        """Extract SSVC data from CISA ADP."""
        for metric in cisa_adp.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type") == "ssvc":
                content = other.get("content", {})
                options = content.get("options", [])
                ssvc = {}
                for opt in options:
                    for k, v in opt.items():
                        ssvc[k.lower().replace(" ", "_")] = v
                return ssvc
        return None

    # --- Helpers ---

    def _find_cisa_adp(self, adp_list: list) -> dict | None:
        """Find the CISA-ADP entry from ADP list."""
        for adp in adp_list:
            short_name = adp.get("providerMetadata", {}).get("shortName", "")
            if short_name == "CISA-ADP":
                return adp
        return None


# ===========================================================================
# Telegram Formatter
# ===========================================================================

class TelegramFormatter:
    """Format normalized CVE data into Telegram HTML message."""

    def format(self, cve: dict, is_new: bool = True, kev_entry: dict | None = None) -> str:
        """Build Telegram HTML message for a CVE."""
        parts = []

        # --- Header ---
        icon = "🔴" if is_new else "🔄"
        label = "NEW CVE PUBLISHED" if is_new else "CVE UPDATED"
        parts.append(f"{icon} <b>{label}</b>\n")

        # CVE ID + Title
        cve_id = html.escape(cve["cve_id"])
        parts.append(f"<b>📌 {cve_id}</b>")
        if cve.get("title"):
            parts.append(f"<i>{html.escape(cve['title'])}</i>")

        # Quick-glance affected vendor/product summary (grouped by vendor)
        vendor_products: dict[str, list[str]] = {}
        for prod in cve.get("affected_products", []):
            vendor = prod.get("vendor", "unknown")
            product = prod.get("product", "unknown")
            vendor_products.setdefault(vendor, []).append(product)

        if vendor_products:
            summary_parts = []
            for vendor, prods in vendor_products.items():
                unique_prods = list(dict.fromkeys(prods))
                if len(unique_prods) <= 3:
                    summary_parts.append(f"{vendor} — {', '.join(unique_prods)}")
                else:
                    summary_parts.append(f"{vendor} — {', '.join(unique_prods[:2])} +{len(unique_prods)-2} khác")
            parts.append(f"🏢 {html.escape(' | '.join(summary_parts[:4]))}")
        parts.append("")

        # Dates
        pub = self._format_date(cve.get("published_date", ""))
        upd = self._format_date(cve.get("last_modified_date", ""))
        parts.append(f"📅 Published: <code>{pub}</code>")
        parts.append(f"📅 Updated:   <code>{upd}</code>")
        if cve.get("assigner"):
            parts.append(f"🏷️ Source:    {html.escape(cve['assigner'])}")
        parts.append("")

        # --- Severity ---
        parts.append("━━━━━ SEVERITY ━━━━━")
        if cve["cvss_score"] is not None:
            sev = html.escape(cve.get("cvss_severity", ""))
            parts.append(f"⚠️ CVSS {cve['cvss_version']}: <b>{cve['cvss_score']} / 10</b>  ({sev})")
            if cve.get("cvss_vector"):
                parts.append(f"🔗 <code>{html.escape(cve['cvss_vector'])}</code>")
        else:
            parts.append("⚠️ CVSS: <b>Chưa có đánh giá</b>")
        parts.append("")

        # --- Weakness ---
        parts.append("━━━━━ WEAKNESS ━━━━━")
        for w in cve.get("weaknesses", []):
            parts.append(f"🧩 {html.escape(w)}")
        parts.append("")

        # --- Affected (grouped by vendor for compact display) ---
        parts.append("━━━━━ AFFECTED ━━━━━")
        affected_prods = cve.get("affected_products", [])
        many_products = len(affected_prods) > 5

        # Group by vendor
        vendor_groups: dict[str, list[dict]] = {}
        for prod in affected_prods:
            v = prod.get("vendor", "unknown")
            vendor_groups.setdefault(v, []).append(prod)

        for vendor_name, prods in vendor_groups.items():
            vendor_esc = html.escape(vendor_name)

            if many_products:
                # Compact mode: one line per product, group under vendor header
                parts.append(f"🏢 <b>{vendor_esc}</b>")
                for prod in prods:
                    product = html.escape(prod.get("product", "unknown"))
                    pkg = html.escape(prod.get("package_name", ""))
                    prod_label = product
                    if pkg and pkg != prod.get("product", ""):
                        prod_label += f" ({pkg})"

                    # Combine version info into one line
                    ver_parts = []
                    for v in prod.get("versions", []):
                        if v.get("type") == "fixed":
                            ver_parts.append(f"✅ {v['display']}")
                        elif v.get("type") != "unknown" or v.get("display") != "Chưa xác định":
                            ver_parts.append(v["display"])
                    ver_str = " → ".join(ver_parts) if ver_parts else "Chưa xác định"
                    parts.append(f"   📦 {html.escape(prod_label)}: {html.escape(ver_str)}")
            else:
                # Normal mode: detailed per product
                for prod in prods:
                    product = html.escape(prod.get("product", "unknown"))
                    pkg = html.escape(prod.get("package_name", ""))
                    label = f"🏢 <b>{vendor_esc}</b> — {product}"
                    if pkg and pkg != prod.get("product", ""):
                        label += f" ({pkg})"
                    parts.append(label)

                    affected_vers = []
                    fixed_vers = []
                    for v in prod.get("versions", []):
                        if v.get("type") == "fixed":
                            fixed_vers.append(v["display"])
                        elif v.get("type") != "unknown" or v.get("display") != "Chưa xác định":
                            affected_vers.append(v["display"])

                    for av in affected_vers:
                        parts.append(f"   📎 {html.escape(av)}")
                    for fv in fixed_vers:
                        parts.append(f"   ✅ {html.escape(fv)}")

                    if not affected_vers and not fixed_vers:
                        parts.append("   📎 Chưa xác định")
        parts.append("")

        # --- Description (truncated) ---
        parts.append("━━━━━ DESCRIPTION ━━━━━")
        desc = cve.get("description", "")
        if desc:
            # Reserve space for the rest of the message
            current_len = sum(len(p) for p in parts)
            remaining = TELEGRAM_MAX_LEN - current_len - 600  # buffer for sections below
            if len(desc) > remaining and remaining > 100:
                desc = desc[:remaining].rsplit(" ", 1)[0] + "..."
            parts.append(html.escape(desc))
        else:
            parts.append("Không có mô tả.")
        parts.append("")

        # --- POC / Exploit ---
        poc = cve.get("poc_exploit", {})
        if poc.get("has_poc"):
            parts.append("━━━━━ EXPLOIT / POC ━━━━━")
            parts.append("🔥 POC: <b>YES</b>")
            for src in poc.get("sources", [])[:3]:  # Limit to 3 sources
                short = self._shorten_url_label(src)
                parts.append(f'🔗 <a href="{html.escape(src)}">{html.escape(short)}</a>')
            parts.append("")

        # --- CISA ---
        ssvc = cve.get("cisa_ssvc")
        in_kev = kev_entry is not None
        if ssvc or in_kev:
            parts.append("━━━━━ CISA ━━━━━")
            if in_kev:
                parts.append("🛡️ KEV: <b>YES — Known Exploited Vulnerability</b>")
                if kev_entry.get("dueDate"):
                    parts.append(f"⏰ Deadline: <code>{kev_entry['dueDate']}</code>")
            else:
                parts.append("🛡️ KEV: No")
            if ssvc:
                ssvc_parts = []
                if "exploitation" in ssvc:
                    ssvc_parts.append(f"Exploitation={ssvc['exploitation']}")
                if "automatable" in ssvc:
                    ssvc_parts.append(f"Automatable={ssvc['automatable']}")
                if "technical_impact" in ssvc:
                    ssvc_parts.append(f"Impact={ssvc['technical_impact']}")
                if ssvc_parts:
                    parts.append(f"📊 SSVC: {' | '.join(ssvc_parts)}")
            parts.append("")

        # --- References (compact) ---
        refs = cve.get("references", [])
        if refs:
            parts.append("━━━━━ REFERENCES ━━━━━")
            for ref in refs[:5]:  # Limit to 5
                url = ref.get("url", "")
                label = self._shorten_url_label(url)
                tags = ref.get("tags", [])
                tag_str = f" [{', '.join(tags)}]" if tags else ""
                parts.append(f'🔗 <a href="{html.escape(url)}">{html.escape(label)}</a>{html.escape(tag_str)}')

        message = "\n".join(parts)

        # Final safety truncation
        if len(message) > TELEGRAM_MAX_LEN:
            message = message[:TELEGRAM_MAX_LEN - 20] + "\n\n⚠️ [truncated]"

        return message

    def _format_date(self, iso_str: str) -> str:
        """Format ISO date to YYYY-MM-DD HH:MM UTC."""
        if not iso_str:
            return "N/A"
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            return iso_str[:19]

    def _shorten_url_label(self, url: str) -> str:
        """Create a short readable label from a URL."""
        url = url.rstrip("/")
        # GitHub advisory
        m = re.search(r"(GHSA-[\w-]+)", url)
        if m:
            return m.group(1)
        # Git commit
        m = re.search(r"/commit/([a-f0-9]{7,})", url)
        if m:
            return f"Commit {m.group(1)[:12]}"
        # ZDI
        m = re.search(r"(ZDI-\d+-\d+)", url)
        if m:
            return m.group(1)
        # General: last path segment
        parts = url.split("/")
        if len(parts) > 3:
            return parts[2] + "/.../" + parts[-1][:40]
        return url[:60]


# ===========================================================================
# Telegram Sender
# ===========================================================================

class TelegramSender:
    """Send messages via Telegram Bot API."""

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send(self, message: str) -> bool:
        """Send HTML message to Telegram. Returns True on success."""
        url = TELEGRAM_API.format(token=self.bot_token)
        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            resp = requests.post(url, json=payload, timeout=15)
            if resp.status_code == 200:
                log.info("Telegram message sent successfully")
                return True
            else:
                log.error("Telegram API error %d: %s", resp.status_code, resp.text[:200])
                # Rate limit — wait and retry once
                if resp.status_code == 429:
                    retry_after = resp.json().get("parameters", {}).get("retry_after", 5)
                    log.info("Rate limited, waiting %ds...", retry_after)
                    time.sleep(retry_after)
                    resp = requests.post(url, json=payload, timeout=15)
                    return resp.status_code == 200
                return False
        except Exception as e:
            log.error("Failed to send Telegram message: %s", e)
            return False


# ===========================================================================
# Delta Monitor
# ===========================================================================

class DeltaMonitor:
    """Monitor delta.json for new/updated CVEs."""

    def __init__(self):
        self._state = self._load_state()

    def _load_state(self) -> dict:
        """Load last processed state from file."""
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"last_fetch_time": None, "processed_cves": []}

    def _save_state(self):
        """Persist state to file."""
        STATE_FILE.write_text(
            json.dumps(self._state, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def fetch_delta(self) -> dict | None:
        """Fetch current delta.json from GitHub."""
        try:
            resp = requests.get(DELTA_URL, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.error("Failed to fetch delta.json: %s", e)
            return None

    def fetch_delta_log(self) -> list | None:
        """Fetch deltaLog.json for catchup after downtime."""
        try:
            log.info("Fetching deltaLog.json for catchup...")
            resp = requests.get(DELTA_LOG_URL, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.error("Failed to fetch deltaLog.json: %s", e)
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
        # For new entries, always send. For updated, skip if same fetchTime already seen
        # We keep last 500 processed IDs to avoid memory bloat
        new_entries = [e for e in new_entries if e.get("cveId") not in processed]

        return new_entries, updated_entries

    def mark_processed(self, fetch_time: str, cve_ids: list[str]):
        """Mark a delta snapshot as processed."""
        self._state["last_fetch_time"] = fetch_time
        # Keep last 500 processed CVEs to avoid deduplication issues
        existing = self._state.get("processed_cves", [])
        existing.extend(cve_ids)
        self._state["processed_cves"] = existing[-500:]
        self._save_state()

    def catchup(self) -> list[dict]:
        """
        On first run or after downtime, process missed deltas from deltaLog.json.
        Returns list of delta snapshots to process (oldest first).
        """
        last_time = self._state.get("last_fetch_time")
        if last_time is None:
            log.info("First run — processing only the latest delta")
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
        log.info("Catchup: %d missed delta snapshots since %s", len(missed), last_time)
        return missed

    def fetch_cve_json(self, github_link: str) -> dict | None:
        """Download full CVE JSON from GitHub raw link."""
        try:
            resp = requests.get(github_link, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.error("Failed to fetch CVE JSON from %s: %s", github_link, e)
            return None


# ===========================================================================
# Main
# ===========================================================================

def process_delta(
    delta: dict,
    parser: CVEParser,
    formatter: TelegramFormatter,
    sender: TelegramSender | None,
    kev: KEVLookup,
    monitor: DeltaMonitor,
    dry_run: bool,
):
    """Process a single delta snapshot: parse CVEs and send alerts."""
    new_entries, updated_entries = monitor.get_new_entries(delta)

    if not new_entries and not updated_entries:
        return 0

    total = len(new_entries) + len(updated_entries)
    log.info("Processing %d CVEs (%d new, %d updated)", total, len(new_entries), len(updated_entries))

    processed_ids = []

    for entry in new_entries:
        _process_one(entry, True, parser, formatter, sender, kev, monitor, dry_run)
        processed_ids.append(entry.get("cveId", ""))

    for entry in updated_entries:
        _process_one(entry, False, parser, formatter, sender, kev, monitor, dry_run)
        processed_ids.append(entry.get("cveId", ""))

    monitor.mark_processed(delta.get("fetchTime", ""), processed_ids)
    return total


def _process_one(
    entry: dict,
    is_new: bool,
    parser: CVEParser,
    formatter: TelegramFormatter,
    sender: TelegramSender | None,
    kev: KEVLookup,
    monitor: DeltaMonitor,
    dry_run: bool,
):
    """Process a single CVE entry from delta."""
    cve_id = entry.get("cveId", "")
    github_link = entry.get("githubLink", "")

    if not github_link:
        log.warning("No githubLink for %s, skipping", cve_id)
        return

    # Download full CVE JSON
    raw = monitor.fetch_cve_json(github_link)
    if not raw:
        return

    # Parse
    cve_data = parser.parse(raw)

    # KEV lookup
    kev_entry = kev.lookup(cve_id)

    # Format message
    message = formatter.format(cve_data, is_new=is_new, kev_entry=kev_entry)

    if dry_run:
        print("=" * 60)
        print(f"[DRY RUN] {'NEW' if is_new else 'UPDATED'}: {cve_id}")
        print("=" * 60)
        # Strip HTML for console display
        clean = re.sub(r"<[^>]+>", "", message)
        print(clean)
        print()
    elif sender:
        sender.send(message)
        time.sleep(1)  # Telegram rate limit: ~30 msg/sec, be conservative


def main():
    # Fix Windows console encoding for emoji/unicode output
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(description="CVE Monitor — Telegram Alert Bot")
    ap.add_argument("--bot-token", default=os.environ.get("CVE_BOT_TOKEN", ""), help="Telegram bot token")
    ap.add_argument("--chat-id", default=os.environ.get("CVE_CHAT_ID", ""), help="Telegram chat ID")
    ap.add_argument("--interval", type=int, default=int(os.environ.get("CVE_POLL_INTERVAL", DEFAULT_POLL_INTERVAL)),
                    help=f"Poll interval in seconds (default: {DEFAULT_POLL_INTERVAL})")
    ap.add_argument("--dry-run", action="store_true", help="Print messages to console, don't send Telegram")
    ap.add_argument("--once", action="store_true", help="Process current delta once and exit")
    ap.add_argument("--no-kev", action="store_true", help="Skip CISA KEV catalog download")
    args = ap.parse_args()

    if not args.dry_run and (not args.bot_token or not args.chat_id):
        log.error("--bot-token and --chat-id are required (or set CVE_BOT_TOKEN / CVE_CHAT_ID env vars)")
        sys.exit(1)

    # Initialize components
    parser = CVEParser()
    formatter = TelegramFormatter()
    kev = KEVLookup(enabled=not args.no_kev)
    monitor = DeltaMonitor()
    sender = TelegramSender(args.bot_token, args.chat_id) if not args.dry_run else None

    # Catchup: process missed deltas if any
    missed = monitor.catchup()
    for delta_snapshot in missed:
        process_delta(delta_snapshot, parser, formatter, sender, kev, monitor, args.dry_run)

    # Main loop
    log.info("CVE Monitor started. Polling every %ds. Dry-run=%s", args.interval, args.dry_run)

    try:
        while True:
            delta = monitor.fetch_delta()
            if delta:
                count = process_delta(delta, parser, formatter, sender, kev, monitor, args.dry_run)
                if count:
                    log.info("Processed %d CVEs in this cycle", count)
                else:
                    log.debug("No new changes")

            if args.once:
                log.info("Single-shot mode, exiting")
                break

            time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Shutting down...")


if __name__ == "__main__":
    main()
