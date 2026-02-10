"""
Telegram Formatter — Format normalized CVE data into Telegram HTML message.
"""

import html
import re
from datetime import datetime

TELEGRAM_MAX_LEN = 4096


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
        res = self._format_date(cve.get("reserved_date", ""))
        pub = self._format_date(cve.get("published_date", ""))
        upd = self._format_date(cve.get("last_modified_date", ""))
        parts.append(f"📅 Reserved:  <code>{res}</code>")
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
