# ======================================================
# CLOUDGUARD V2
# RESOURCE DISCOVERY ENGINE
# ======================================================

from cloud_simulator import get_cloud_resources


def discover_resources():

    resources = get_cloud_resources()

    discovered_resources = []

    for resource in resources:

        discovered_resources.append({
            "id": resource["id"],
            "name": resource["name"],
            "type": resource["type"],
            "provider": resource["provider"],
            "region": resource["region"]
        })

    return discovered_resources


# ======================================================
# RESOURCE SUMMARY
# ======================================================

def get_resource_summary(resources):

    summary = {
        "total": len(resources),
        "servers": 0,
        "storage": 0,
        "databases": 0,
        "security_groups": 0,
        "iam_users": 0
    }

    for resource in resources:

        resource_type = resource["type"]

        if resource_type == "server":
            summary["servers"] += 1

        elif resource_type == "storage":
            summary["storage"] += 1

        elif resource_type == "database":
            summary["databases"] += 1

        elif resource_type == "security_group":
            summary["security_groups"] += 1

        elif resource_type == "iam_user":
            summary["iam_users"] += 1

    return summary


# ======================================================
# TEST RESOURCE DISCOVERY
# ======================================================

if __name__ == "__main__":

    resources = discover_resources()

    summary = get_resource_summary(resources)

    print("\n==========================================")
    print("       CLOUDGUARD V2 RESOURCE DISCOVERY")
    print("==========================================\n")

    print(f"Total Resources: {summary['total']}")
    print(f"Servers: {summary['servers']}")
    print(f"Storage: {summary['storage']}")
    print(f"Databases: {summary['databases']}")
    print(f"Security Groups: {summary['security_groups']}")
    print(f"IAM Users: {summary['iam_users']}")

    print("\n------------------------------------------")
    print("DISCOVERED RESOURCES")
    print("------------------------------------------\n")

    for resource in resources:

        print(
            f"[{resource['type'].upper()}] "
            f"{resource['name']} "
            f"| {resource['region']}"
        )

    print("\n==========================================")
    print("Resource discovery completed.")
    print("==========================================")