# ======================================================
# CLOUDGUARD V2
# LOCAL CLOUD SIMULATOR
# ======================================================

def get_cloud_resources():

    resources = [

        # ==================================================
        # COMPUTE
        # ==================================================

        {
            "id": "i-001",
            "name": "WebServer-01",
            "type": "server",
            "provider": "CloudGuard-Cloud",
            "region": "Mumbai",
            "ssh_allowed_ip": "0.0.0.0/0",
            "encryption_enabled": False,
            "logging_enabled": False,
            "public_access": False
        },

        {
            "id": "i-002",
            "name": "WebServer-02",
            "type": "server",
            "provider": "CloudGuard-Cloud",
            "region": "Mumbai",
            "ssh_allowed_ip": "192.168.1.0/24",
            "encryption_enabled": True,
            "logging_enabled": True,
            "public_access": False
        },

        {
            "id": "i-003",
            "name": "AdminServer",
            "type": "server",
            "provider": "CloudGuard-Cloud",
            "region": "Pune",
            "ssh_allowed_ip": "10.0.0.0/8",
            "encryption_enabled": True,
            "logging_enabled": True,
            "public_access": False
        },


        # ==================================================
        # STORAGE
        # ==================================================

        {
            "id": "bucket-001",
            "name": "Storage-Bucket-01",
            "type": "storage",
            "provider": "CloudGuard-Cloud",
            "region": "Mumbai",
            "encryption_enabled": False,
            "public_access": True
        },

        {
            "id": "bucket-002",
            "name": "Storage-Bucket-02",
            "type": "storage",
            "provider": "CloudGuard-Cloud",
            "region": "Pune",
            "encryption_enabled": True,
            "public_access": False
        },


        # ==================================================
        # DATABASE
        # ==================================================

        {
            "id": "db-001",
            "name": "Database-01",
            "type": "database",
            "provider": "CloudGuard-Cloud",
            "region": "Mumbai",
            "encryption_enabled": True,
            "public_access": True
        },

        {
            "id": "db-002",
            "name": "Database-02",
            "type": "database",
            "provider": "CloudGuard-Cloud",
            "region": "Pune",
            "encryption_enabled": True,
            "public_access": False
        },


        # ==================================================
        # NETWORK
        # ==================================================

        {
            "id": "sg-001",
            "name": "SecurityGroup-Web",
            "type": "security_group",
            "provider": "CloudGuard-Cloud",
            "region": "Mumbai",
            "ssh_allowed_ip": "0.0.0.0/0",
            "http_allowed": True,
            "https_allowed": True
        },

        {
            "id": "sg-002",
            "name": "SecurityGroup-DB",
            "type": "security_group",
            "provider": "CloudGuard-Cloud",
            "region": "Mumbai",
            "ssh_allowed_ip": "10.0.0.0/8",
            "http_allowed": False,
            "https_allowed": False
        },


        # ==================================================
        # IAM
        # ==================================================

        {
            "id": "user-001",
            "name": "AdminUser",
            "type": "iam_user",
            "provider": "CloudGuard-Cloud",
            "region": "Global",
            "mfa_enabled": True,
            "admin_privileges": True
        },

        {
            "id": "user-002",
            "name": "DeveloperUser",
            "type": "iam_user",
            "provider": "CloudGuard-Cloud",
            "region": "Global",
            "mfa_enabled": False,
            "admin_privileges": False
        }

    ]

    return resources


# ======================================================
# TEST CLOUD SIMULATOR
# ======================================================

if __name__ == "__main__":

    resources = get_cloud_resources()

    print("\n==========================================")
    print("       CLOUDGUARD V2 CLOUD SIMULATOR")
    print("==========================================\n")

    print(f"Total Resources Discovered: {len(resources)}\n")

    for resource in resources:

        print(
            f"{resource['name']} "
            f"({resource['type']}) "
            f"- {resource['region']}"
        )

    print("\n==========================================")
    print("Cloud simulation completed.")
    print("==========================================")