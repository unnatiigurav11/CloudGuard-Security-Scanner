# ======================================================
# CLOUDGUARD V2
# SECURITY POLICY ENGINE
# ======================================================

from cloud_simulator import get_cloud_resources


# ======================================================
# CHECK SERVER SECURITY
# ======================================================

def check_server(resource):

    findings = []

    resource_name = resource["name"]

    # --------------------------------------------------
    # Policy 1: SSH should not be open to everyone
    # --------------------------------------------------

    if resource.get("ssh_allowed_ip") == "0.0.0.0/0":

        findings.append({
            "resource": resource_name,
            "resource_type": "server",
            "policy": "SSH Access Control",
            "issue": "SSH exposed to the Internet",
            "severity": "HIGH",
            "description": (
                "SSH access is allowed from any IP address."
            ),
            "recommendation": (
                "Restrict SSH access to trusted IP addresses."
            )
        })

    # --------------------------------------------------
    # Policy 2: Encryption
    # --------------------------------------------------

    if not resource.get("encryption_enabled", True):

        findings.append({
            "resource": resource_name,
            "resource_type": "server",
            "policy": "Data Encryption",
            "issue": "Encryption disabled",
            "severity": "MEDIUM",
            "description": (
                "Data encryption is not enabled."
            ),
            "recommendation": (
                "Enable encryption for stored data."
            )
        })

    # --------------------------------------------------
    # Policy 3: Logging
    # --------------------------------------------------

    if not resource.get("logging_enabled", True):

        findings.append({
            "resource": resource_name,
            "resource_type": "server",
            "policy": "Security Logging",
            "issue": "Logging disabled",
            "severity": "LOW",
            "description": (
                "Security logging is not enabled."
            ),
            "recommendation": (
                "Enable logging for security monitoring."
            )
        })

    return findings


# ======================================================
# CHECK STORAGE SECURITY
# ======================================================

def check_storage(resource):

    findings = []

    resource_name = resource["name"]

    # --------------------------------------------------
    # Policy 4: Public storage
    # --------------------------------------------------

    if resource.get("public_access") is True:

        findings.append({
            "resource": resource_name,
            "resource_type": "storage",
            "policy": "Public Access Control",
            "issue": "Public storage access enabled",
            "severity": "CRITICAL",
            "description": (
                "The storage resource is publicly accessible."
            ),
            "recommendation": (
                "Disable public access unless explicitly required."
            )
        })

    # --------------------------------------------------
    # Policy 5: Storage encryption
    # --------------------------------------------------

    if not resource.get("encryption_enabled", True):

        findings.append({
            "resource": resource_name,
            "resource_type": "storage",
            "policy": "Storage Encryption",
            "issue": "Storage encryption disabled",
            "severity": "MEDIUM",
            "description": (
                "Stored data is not protected by encryption."
            ),
            "recommendation": (
                "Enable encryption for the storage resource."
            )
        })

    return findings


# ======================================================
# CHECK DATABASE SECURITY
# ======================================================

def check_database(resource):

    findings = []

    resource_name = resource["name"]

    # --------------------------------------------------
    # Policy 6: Public database
    # --------------------------------------------------

    if resource.get("public_access") is True:

        findings.append({
            "resource": resource_name,
            "resource_type": "database",
            "policy": "Database Access Control",
            "issue": "Database publicly accessible",
            "severity": "CRITICAL",
            "description": (
                "The database can be accessed publicly."
            ),
            "recommendation": (
                "Restrict database access to trusted networks."
            )
        })

    # --------------------------------------------------
    # Policy 7: Database encryption
    # --------------------------------------------------

    if not resource.get("encryption_enabled", True):

        findings.append({
            "resource": resource_name,
            "resource_type": "database",
            "policy": "Database Encryption",
            "issue": "Database encryption disabled",
            "severity": "HIGH",
            "description": (
                "Database data is not encrypted."
            ),
            "recommendation": (
                "Enable encryption for the database."
            )
        })

    return findings


# ======================================================
# CHECK SECURITY GROUP
# ======================================================

def check_security_group(resource):

    findings = []

    resource_name = resource["name"]

    # --------------------------------------------------
    # Policy 8: SSH exposed through security group
    # --------------------------------------------------

    if resource.get("ssh_allowed_ip") == "0.0.0.0/0":

        findings.append({
            "resource": resource_name,
            "resource_type": "security_group",
            "policy": "Network Access Control",
            "issue": "SSH open to the Internet",
            "severity": "HIGH",
            "description": (
                "The security group allows SSH access "
                "from any IP address."
            ),
            "recommendation": (
                "Restrict SSH to trusted networks or IP ranges."
            )
        })

    return findings


# ======================================================
# CHECK IAM SECURITY
# ======================================================

def check_iam_user(resource):

    findings = []

    resource_name = resource["name"]

    # --------------------------------------------------
    # Policy 9: MFA
    # --------------------------------------------------

    if not resource.get("mfa_enabled", True):

        findings.append({
            "resource": resource_name,
            "resource_type": "iam_user",
            "policy": "Multi-Factor Authentication",
            "issue": "MFA is disabled",
            "severity": "HIGH",
            "description": (
                "Multi-factor authentication is not enabled "
                "for this user."
            ),
            "recommendation": (
                "Enable MFA for the user account."
            )
        })

    return findings


# ======================================================
# MAIN POLICY ENGINE
# ======================================================

def evaluate_resource(resource):

    resource_type = resource["type"]

    if resource_type == "server":
        return check_server(resource)

    elif resource_type == "storage":
        return check_storage(resource)

    elif resource_type == "database":
        return check_database(resource)

    elif resource_type == "security_group":
        return check_security_group(resource)

    elif resource_type == "iam_user":
        return check_iam_user(resource)

    return []


# ======================================================
# RUN SECURITY POLICIES
# ======================================================

def run_policy_checks():

    resources = get_cloud_resources()

    all_findings = []

    for resource in resources:

        findings = evaluate_resource(resource)

        all_findings.extend(findings)

    return all_findings


# ======================================================
# TEST POLICY ENGINE
# ======================================================

if __name__ == "__main__":

    findings = run_policy_checks()

    print("\n==========================================")
    print("       CLOUDGUARD V2 POLICY ENGINE")
    print("==========================================\n")

    if not findings:

        print("No security issues found.")

    else:

        print(
            f"Security findings detected: "
            f"{len(findings)}\n"
        )

        for finding in findings:

            print(
                f"Resource: "
                f"{finding['resource']}"
            )

            print(
                f"Policy: "
                f"{finding['policy']}"
            )

            print(
                f"Issue: "
                f"{finding['issue']}"
            )

            print(
                f"Severity: "
                f"{finding['severity']}"
            )

            print(
                f"Description: "
                f"{finding['description']}"
            )

            print(
                f"Recommendation: "
                f"{finding['recommendation']}"
            )

            print("-" * 50)

    print("\n==========================================")
    print("Policy evaluation completed.")
    print("==========================================")