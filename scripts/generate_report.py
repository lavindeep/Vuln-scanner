"""
Dashboard Report Generator

Aggregates outputs from Trivy, Syft, OPA, and the compliance mapper into a
single markdown dashboard (dashboard.md) readable by a non-technical reviewer
such as a program manager or ATO reviewer.

Uses only Python standard library — no pip install needed in CI.
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def _load_json(path: str) -> dict | None:
    """Load a JSON file, returning None if missing or malformed."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _extract_vulns(trivy_data: dict | None) -> list[dict]:
    """Flatten all vulnerabilities from Trivy results."""
    if not trivy_data:
        return []
    vulns = []
    for result in trivy_data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            vulns.append(v)
    return vulns


def _extract_opa_violations(opa_data: dict | None) -> list[str]:
    """Extract violation messages from OPA eval JSON output."""
    if not opa_data:
        return []
    try:
        value = opa_data["result"][0]["expressions"][0]["value"]
        return list(value.get("violation", []))
    except (KeyError, IndexError, TypeError):
        return []


def _severity_rank(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}.get(severity, -1)


def generate_dashboard() -> str:
    """Generate the full dashboard markdown."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Load all inputs
    trivy_data = _load_json("trivy-results.json")
    sbom_data = _load_json("sbom.cyclonedx.json")
    opa_data = _load_json("opa-output.json")
    compliance_exists = Path("compliance-report.md").exists()

    vulns = _extract_vulns(trivy_data)
    opa_violations = _extract_opa_violations(opa_data)

    # Severity counts
    severity_counts = Counter(v.get("Severity", "UNKNOWN") for v in vulns)
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)

    # SBOM info
    sbom_components = len(sbom_data.get("components", [])) if sbom_data else 0

    # Overall status
    pipeline_passed = critical == 0 and high == 0 and len(opa_violations) == 0

    # Scan metadata
    artifact_name = trivy_data.get("ArtifactName", "Unknown") if trivy_data else "Unknown"
    created_at = trivy_data.get("CreatedAt", "Unknown") if trivy_data else "Unknown"

    lines = []

    # ── Header ───────────────────────────────────────────────────────────
    lines.append("# Security Scan Dashboard")
    lines.append("")
    lines.append(f"**Scan Date:** {now}")
    lines.append(f"**Image:** `{artifact_name}`")
    lines.append("")

    # ── Overall Status ───────────────────────────────────────────────────
    if pipeline_passed:
        lines.append("> [!NOTE]")
        lines.append("> **Pipeline Status: PASS** — No critical or high vulnerabilities detected. All policies satisfied.")
    else:
        lines.append("> [!CAUTION]")
        lines.append("> **Pipeline Status: FAIL** — Security issues detected. Review findings below.")
    lines.append("")

    # ── Vulnerability Summary ────────────────────────────────────────────
    lines.append("## Vulnerability Summary")
    lines.append("")
    lines.append("| Severity | Count | Status |")
    lines.append("|----------|-------|--------|")
    lines.append(f"| CRITICAL | {critical} | {'FAIL' if critical > 0 else 'PASS'} |")
    lines.append(f"| HIGH | {high} | {'FAIL' if high > 0 else 'PASS'} |")
    lines.append(f"| MEDIUM | {medium} | INFO |")
    lines.append(f"| LOW | {low} | INFO |")
    lines.append(f"| **Total** | **{len(vulns)}** | |")
    lines.append("")

    # ── Policy Violations ────────────────────────────────────────────────
    lines.append("## Policy Violations")
    lines.append("")
    if opa_violations:
        for i, violation in enumerate(opa_violations, 1):
            lines.append(f"{i}. {violation}")
    else:
        lines.append("No policy violations detected.")
    lines.append("")

    # ── Top 5 Critical Findings ──────────────────────────────────────────
    lines.append("## Top Findings")
    lines.append("")
    top_vulns = sorted(vulns, key=lambda v: _severity_rank(v.get("Severity", "")), reverse=True)[:5]
    if top_vulns:
        lines.append("| CVE ID | Severity | Package | Installed | Fixed | Published |")
        lines.append("|--------|----------|---------|-----------|-------|-----------|")
        for v in top_vulns:
            cve = v.get("VulnerabilityID", "N/A")
            sev = v.get("Severity", "N/A")
            pkg = v.get("PkgName", "N/A")
            installed = v.get("InstalledVersion", "N/A")
            fixed = v.get("FixedVersion", "") or "No fix"
            published = v.get("PublishedDate", "N/A")
            if published != "N/A":
                published = published[:10]  # Just the date portion
            lines.append(f"| {cve} | {sev} | {pkg} | {installed} | {fixed} | {published} |")
    else:
        lines.append("No vulnerabilities detected.")
    lines.append("")

    # ── SBOM Status ──────────────────────────────────────────────────────
    lines.append("## SBOM Status")
    lines.append("")
    if sbom_data:
        lines.append(f"CycloneDX SBOM generated successfully with **{sbom_components} components** cataloged.")
        lines.append("")
        lines.append("This satisfies Executive Order 14028 Section 4(e) requiring SBOMs for")
        lines.append("software sold to the federal government.")
    else:
        lines.append("SBOM generation did not complete. Check the Syft step logs.")
    lines.append("")

    # ── Compliance Report ────────────────────────────────────────────────
    lines.append("## Compliance Report")
    lines.append("")
    if compliance_exists:
        lines.append("NIST 800-53 compliance report generated. See `compliance-report.md` artifact for")
        lines.append("full control mappings (SI-2, RA-5, CM-6, CM-7, SA-11, SC-28).")
    else:
        lines.append("Compliance report was not generated. Check the compliance mapper step logs.")
    lines.append("")

    # ── Scan Metadata ────────────────────────────────────────────────────
    lines.append("## Scan Metadata")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Image | `{artifact_name}` |")
    lines.append(f"| Scan Timestamp | {created_at} |")
    lines.append(f"| Report Generated | {now} |")
    lines.append(f"| SBOM Components | {sbom_components} |")
    lines.append(f"| Total Vulnerabilities | {len(vulns)} |")
    lines.append(f"| Policy Violations | {len(opa_violations)} |")
    lines.append("")

    return "\n".join(lines)


def main():
    report = generate_dashboard()
    output_path = Path("dashboard.md")
    output_path.write_text(report)
    print(f"✅ Dashboard written to {output_path}")


if __name__ == "__main__":
    main()
