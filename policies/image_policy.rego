package image_policy

import rego.v1

# ── Rule 1: No CRITICAL CVEs ────────────────────────────────────────────────
# Any CRITICAL severity finding is an automatic policy violation.

violation contains msg if {
	some result in input.Results
	some vuln in result.Vulnerabilities
	vuln.Severity == "CRITICAL"
	msg := sprintf("CRITICAL CVE found: %s in package %s (%s)", [
		vuln.VulnerabilityID,
		vuln.PkgName,
		vuln.InstalledVersion,
	])
}

# ── Rule 2: Max CVE Age (90 days) ───────────────────────────────────────────
# CVEs older than 90 days that have a fix available indicate the image is not
# being patched in a timely manner.

violation contains msg if {
	some result in input.Results
	some vuln in result.Vulnerabilities
	vuln.FixedVersion != ""
	published_ns := time.parse_rfc3339_ns(vuln.PublishedDate)
	age_days := (time.now_ns() - published_ns) / (24 * 60 * 60 * 1000000000)
	age_days > 90
	msg := sprintf("CVE %s is %.0f days old with available fix (upgrade %s to %s)", [
		vuln.VulnerabilityID,
		age_days,
		vuln.InstalledVersion,
		vuln.FixedVersion,
	])
}

# ── Rule 3: Required Docker Labels ──────────────────────────────────────────
# The image must have maintainer, version, and description labels for audit
# traceability. These are set via LABEL instructions in the Dockerfile.

required_labels := {"maintainer", "version", "description"}

violation contains msg if {
	some label in required_labels
	not _has_label(label)
	msg := sprintf("Required Docker label missing: %s", [label])
}

# Helper: check if a label exists in the Trivy metadata.
# The path may vary across Trivy versions — try both known locations.
_has_label(label) if {
	input.Metadata.ImageConfig.Config.Labels[label]
}

_has_label(label) if {
	input.Metadata.ImageConfig.Labels[label]
}
