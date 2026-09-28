import json
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError

PROFILE = "fulmen"
ROLE_PREFIX = "fulmen-demo"
OUTPUT_FILE = "scan_results/iam_roles.json"


def to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_policy_actions(iam, policy_arn):
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = policy["DefaultVersionId"]
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    document = version["PolicyVersion"]["Document"]

    actions = []
    for statement in to_list(document.get("Statement")):
        if statement.get("Effect") == "Allow":
            actions.extend(to_list(statement.get("Action")))
    return actions


def is_wildcard(action):
    return action == "*" or action.endswith(":*")


def main():
    session = boto3.Session(profile_name=PROFILE)
    iam = session.client("iam")

    results = []

    role_paginator = iam.get_paginator("list_roles")
    for page in role_paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            if not role_name.startswith(ROLE_PREFIX):
                continue

            policies = []
            all_actions = []

            policy_paginator = iam.get_paginator("list_attached_role_policies")
            for policy_page in policy_paginator.paginate(RoleName=role_name):
                for policy in policy_page["AttachedPolicies"]:
                    actions = get_policy_actions(iam, policy["PolicyArn"])
                    policies.append({
                        "name": policy["PolicyName"],
                        "arn": policy["PolicyArn"],
                        "actions": actions,
                    })
                    all_actions.extend(actions)

            unique_actions = sorted(set(all_actions))
            results.append({
                "role_name": role_name,
                "role_arn": role["Arn"],
                "policies": policies,
                "all_actions": unique_actions,
                "has_wildcard": any(is_wildcard(a) for a in unique_actions),
            })

    os.makedirs("scan_results", exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print("Roles found:", len(results))
    for item in results:
        print("-", item["role_name"])
        print("  policies:", [p["name"] for p in item["policies"]])
        print("  unique actions:", len(item["all_actions"]))
        print("  wildcard (*) permission:", item["has_wildcard"])
    print("Saved to", OUTPUT_FILE)


if __name__ == "__main__":
    try:
        main()
    except (ClientError, BotoCoreError) as error:
        print("AWS error:", error)