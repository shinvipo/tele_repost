"""
CVE Parser — Parse cvelistV5 JSON records into normalized dicts.
"""

import re


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
            "reserved_date": metadata.get("dateReserved", ""),
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
        if re.match(r"[><= ]", version_val) and "," in version_val:
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
