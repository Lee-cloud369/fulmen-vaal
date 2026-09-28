import json

with open("scan_results/nginx-old.json", "r") as f:
    data = json.load(f)

counts = {"CRITICAL": 0, "HIGH": 0}
findings = []

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []) or []:
        severity = vuln.get("Severity")
        if severity in counts:
            counts[severity] += 1
        findings.append({
            "cve": vuln.get("VulnerabilityID"),
            "package": vuln.get("PkgName"),
            "installed": vuln.get("InstalledVersion"),
            "fixed": vuln.get("FixedVersion", "no fix yet"),
            "severity": severity,
        })

print("Image:", data.get("ArtifactName"))
print("Total findings:", len(findings))
print("CRITICAL:", counts["CRITICAL"])
print("HIGH:", counts["HIGH"])
print()
print("First 5 findings:")
for item in findings[:5]:
    print(item)