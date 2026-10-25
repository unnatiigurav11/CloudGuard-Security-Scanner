import json


def load_configuration():
    with open("config.json", "r") as file:
        return json.load(file)


def scan_resource(resource):
    findings = []

    resource_name = resource["name"]
    resource_type = resource["type"]

    # Check 1: SSH exposed to the internet
    if resource_type == "server":
        if resource.get("ssh_allowed_ip") == "0.0.0.0/0":
            findings.append({
                "resource": resource_name,
                "issue": "SSH exposed to the Internet",
                "severity": "HIGH",
                "description": "SSH access is allowed from any IP address.",
                "recommendation": "Restrict SSH access to trusted IP addresses."
            })

    # Check 2: Encryption
    if not resource.get("encryption_enabled", True):
        findings.append({
            "resource": resource_name,
            "issue": "Encryption disabled",
            "severity": "MEDIUM",
            "description": "Data encryption is not enabled.",
            "recommendation": "Enable encryption for stored data."
        })

    # Check 3: Public storage/database
    if resource.get("public_access") is True:
        findings.append({
            "resource": resource_name,
            "issue": "Public access enabled",
            "severity": "CRITICAL",
            "description": "The resource is accessible publicly.",
            "recommendation": "Disable public access unless explicitly required."
        })

    # Check 4: Logging
    if resource_type == "server":
        if not resource.get("logging_enabled", True):
            findings.append({
                "resource": resource_name,
                "issue": "Logging disabled",
                "severity": "LOW",
                "description": "Security logging is not enabled.",
                "recommendation": "Enable logging for security monitoring."
            })

    return findings


def run_scan():
    configuration = load_configuration()

    all_findings = []

    for resource in configuration["resources"]:
        findings = scan_resource(resource)
        all_findings.extend(findings)

    return all_findings

def calculate_security_score(findings):
    severity_points = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 10,
        "LOW": 5
    }

    total_risk = 0

    for finding in findings:
        severity = finding["severity"]
        total_risk += severity_points.get(severity, 0)

    # Maximum score is 100
    security_score = max(0, 100 - total_risk)

    return security_score

if __name__ == "__main__":
    findings = run_scan()

    print("\n===== CLOUDGUARD SECURITY SCAN =====\n")

    if not findings:
        print("No security issues found.")

    for finding in findings:
        print(f"Resource: {finding['resource']}")
        print(f"Issue: {finding['issue']}")
        print(f"Severity: {finding['severity']}")
        print(f"Description: {finding['description']}")
        print(f"Recommendation: {finding['recommendation']}")
        print("-" * 50)

    # Calculate security score
    security_score = calculate_security_score(findings)

    # Count severity levels
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    print("\n===== SECURITY SUMMARY =====")
    print(f"Critical: {critical}")
    print(f"High: {high}")
    print(f"Medium: {medium}")
    print(f"Low: {low}")
    print(f"\nSecurity Score: {security_score}/100")