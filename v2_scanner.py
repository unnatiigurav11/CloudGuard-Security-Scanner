"""CloudGuard V2 scan orchestration using the local cloud simulator."""
from cloud_simulator import get_cloud_resources
from policy_engine import evaluate_resource

POLICIES_BY_TYPE = {
    "server": [
        ("SSH Access Control", "HIGH", "SSH access should be restricted to trusted IP addresses.", "Restrict SSH access to trusted IP addresses."),
        ("Data Encryption", "MEDIUM", "Data encryption should be enabled.", "Enable encryption for stored data."),
        ("Security Logging", "LOW", "Security logging should be enabled.", "Enable logging for security monitoring."),
    ],
    "storage": [
        ("Public Access Control", "CRITICAL", "Storage should not be publicly accessible unless explicitly required.", "Disable public access unless explicitly required."),
        ("Storage Encryption", "MEDIUM", "Stored data should be encrypted.", "Enable encryption for the storage resource."),
    ],
    "database": [
        ("Database Access Control", "CRITICAL", "Databases should not be publicly accessible.", "Restrict database access to trusted networks."),
        ("Database Encryption", "HIGH", "Database data should be encrypted.", "Enable encryption for the database."),
    ],
    "security_group": [
        ("Network Access Control", "HIGH", "SSH should not be open to all IP addresses.", "Restrict SSH to trusted networks or IP ranges."),
    ],
    "iam_user": [
        ("Multi-Factor Authentication", "HIGH", "MFA should be enabled for each user.", "Enable MFA for the user account."),
    ],
}


def count_findings(findings):
    return {level.lower(): sum(1 for f in findings if f.get("severity") == level)
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}


def run_v2_scan():
    # Read the simulated environment once so discovery and policy evaluation are consistent.
    raw_resources = get_cloud_resources()
    resources = [{"id": r["id"], "name": r["name"], "type": r["type"],
                  "provider": r.get("provider", "CloudGuard-Cloud"), "region": r.get("region", "Unknown")}
                 for r in raw_resources]
    checks = []
    findings = []

    for resource in raw_resources:
        resource_findings = evaluate_resource(resource)
        failed_by_policy = {f["policy"]: f for f in resource_findings}
        for policy, severity, description, recommendation in POLICIES_BY_TYPE.get(resource.get("type"), []):
            failed = failed_by_policy.get(policy)
            check = {
                "resource_id": resource["id"], "resource": resource["name"],
                "resource_type": resource["type"], "policy": policy,
                "passed": failed is None, "severity": failed.get("severity", severity) if failed else severity,
                "issue": failed.get("issue", "Passed") if failed else "Passed",
                "description": failed.get("description", description) if failed else description,
                "recommendation": failed.get("recommendation", recommendation) if failed else recommendation,
            }
            checks.append(check)
            if failed:
                finding = dict(failed)
                finding["resource_id"] = resource["id"]
                findings.append(finding)

    total_checks = len(checks)
    failed_checks = sum(1 for check in checks if not check["passed"])
    passed_checks = total_checks - failed_checks
    security_score = round((passed_checks / total_checks) * 100) if total_checks else 100
    severity_counts = count_findings(findings)

    # Add the current risk status to resource snapshots returned to callers.
    risky_ids = {f["resource_id"] for f in findings}
    for resource in resources:
        resource["status"] = "AT RISK" if resource["id"] in risky_ids else "SECURE"

    return {
        "resources": resources, "findings": findings, "checks": checks,
        "security_score": security_score, "total_checks": total_checks,
        "passed_checks": passed_checks, "failed_checks": failed_checks,
        "severity_counts": severity_counts, "total_findings": len(findings),
        "total_resources": len(resources),
        "secure_resources": sum(1 for r in resources if r["status"] == "SECURE"),
        "risky_resources": sum(1 for r in resources if r["status"] == "AT RISK"),
        **severity_counts,
    }


if __name__ == "__main__":
    result = run_v2_scan()
    print("\n=== CLOUDGUARD V2 SECURITY SCAN ===")
    for key in ("total_resources", "total_checks", "passed_checks", "failed_checks", "total_findings", "security_score"):
        print(f"{key.replace('_', ' ').title()}: {result[key]}")
    print("Severity:", result["severity_counts"])
    for finding in result["findings"]:
        print(f"[{finding['severity']}] {finding['resource']} — {finding['policy']}: {finding['issue']}")
