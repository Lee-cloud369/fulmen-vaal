import json
import os

SCAN_DIR = "scan_results"
WORKLOADS_FILE = "workloads.json"
IAM_FILE = os.path.join(SCAN_DIR, "iam_roles.json")
REPORT_FILE = os.path.join(SCAN_DIR, "blast_radius_report.json")

VULN_SCALE = 4
IAM_FIXED_SCORE = 25


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def summarize_scan(path):
    data = load_json(path)
    counts = {"critical": 0, "high": 0, "fixable_critical": 0, "fixable_high": 0}
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity")
            if severity == "CRITICAL":
                key = "critical"
            elif severity == "HIGH":
                key = "high"
            else:
                continue
            counts[key] += 1
            if vuln.get("FixedVersion"):
                counts["fixable_" + key] += 1
    return counts


def vuln_score(critical, high):
    raw = critical * 5 + high
    return min(100, round(raw / VULN_SCALE))


def iam_score(role):
    if role["has_wildcard"]:
        return 100
    return min(50, len(role["all_actions"]) * 5)


def calc_blast(v_score, i_score):
    return round(v_score * i_score / 100)


def risk_level(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    return "LOW"


def recommendation(total, fixable, wildcard):
    steps = []
    if fixable > 0:
        steps.append("Update image: " + str(fixable) + " of " + str(total) + " findings have a fix")
    else:
        steps.append("No vendor fixes available yet, monitor and restrict exposure")
    if wildcard:
        steps.append("Replace wildcard IAM permissions with least-privilege policy")
    return steps


def best_first_action(scenarios):
    now = scenarios["current"]
    image = scenarios["after_image_update"]
    iam = scenarios["after_iam_fix"]
    if image >= now and iam >= now:
        return "No single action reduces the score"
    if iam <= image:
        return "Fix IAM permissions first"
    return "Update the image first"


def main():
    workloads = load_json(WORKLOADS_FILE)
    roles = {r["role_name"]: r for r in load_json(IAM_FILE)}

    report = []
    for w in workloads:
        role = roles.get(w["role_name"])
        if role is None:
            print("Role not found for", w["name"], "->", w["role_name"])
            continue

        counts = summarize_scan(os.path.join(SCAN_DIR, w["scan_file"]))
        critical = counts["critical"]
        high = counts["high"]
        fixable = counts["fixable_critical"] + counts["fixable_high"]
        total = critical + high

        v_now = vuln_score(critical, high)
        v_after = vuln_score(critical - counts["fixable_critical"],
                             high - counts["fixable_high"])
        i_now = iam_score(role)
        i_after = min(i_now, IAM_FIXED_SCORE)

        scenarios = {
            "current": calc_blast(v_now, i_now),
            "after_image_update": calc_blast(v_after, i_now),
            "after_iam_fix": calc_blast(v_now, i_after),
            "after_both": calc_blast(v_after, i_after),
        }

        report.append({
            "workload": w["name"],
            "image": w["image"],
            "role": w["role_name"],
            "critical_vulns": critical,
            "high_vulns": high,
            "fixable_vulns": fixable,
            "vuln_score": v_now,
            "iam_score": i_now,
            "wildcard_role": role["has_wildcard"],
            "blast_radius_score": scenarios["current"],
            "risk_level": risk_level(scenarios["current"]),
            "what_if": scenarios,
            "best_first_action": best_first_action(scenarios),
            "recommendations": recommendation(total, fixable, role["has_wildcard"]),
        })

    report.sort(key=lambda item: item["blast_radius_score"], reverse=True)

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)

    print("BLAST RADIUS REPORT")
    for item in report:
        sc = item["what_if"]
        print(item["risk_level"], item["blast_radius_score"], "|", item["workload"],
              "|", item["image"], "->", item["role"])
        print("   vuln score:", item["vuln_score"], "| iam score:", item["iam_score"],
              "| critical:", item["critical_vulns"], "| high:", item["high_vulns"],
              "| fixable:", item["fixable_vulns"])
        print("   what-if -> now:", sc["current"],
              "| image update:", sc["after_image_update"],
              "| IAM fix:", sc["after_iam_fix"],
              "| both:", sc["after_both"])
        print("   best first action:", item["best_first_action"])
        for step in item["recommendations"]:
            print("   >", step)
    print("Saved to", REPORT_FILE)


if __name__ == "__main__":
    main()