\# FULMEN VAAL (Lightning Blade)



\*\*A Container-to-Cloud Blast Radius Correlation Engine\*\* by Pluma Security



Most scanners report container vulnerabilities and IAM permissions separately. FULMEN VAAL correlates them: the same vulnerable image is far more dangerous when the workload runs with a powerful IAM role, and far less dangerous with a least-privilege one.



\## How it works



1\. \*\*Container scan\*\*: Trivy scans an image for HIGH and CRITICAL vulnerabilities (JSON output).

2\. \*\*IAM fetch\*\*: `fetch\_iam\_roles.py` reads role policies with a read-only AWS profile and flags wildcard permissions.

3\. \*\*Correlation\*\*: `correlate.py` maps each workload (`workloads.json`) to its image scan and IAM role, then calculates a blast radius score.

4\. \*\*What-if simulator\*\*: shows the score after an image update, after an IAM fix, and after both, then recommends what to fix first.



\## Scoring model



\- Vulnerability score = `min(100, round((critical x 5 + high) / 4))`

\- IAM score = `100` if the role has a wildcard permission, otherwise `min(50, actions x 5)`

\- Blast radius = `vulnerability score x IAM score / 100`



These weights are my own heuristic, not an industry standard. They are constants at the top of `correlate.py` and are easy to tune.



\## Example result (sample\_output/)



| Workload | Image | Role | Blast radius | Best first action |

|---|---|---|---|---|

| payments-web | nginx:1.19 | webapp (S3 full access) | 89 CRITICAL | Update image |

| docs-site | nginx:1.27 | webapp (S3 full access) | 52 HIGH | Fix IAM permissions |

| reports-viewer | nginx:1.19 | lowrisk (S3 read only) | 22 MEDIUM | Update image |



Note that `payments-web` and `reports-viewer` run the same image. Only the IAM role differs, and the blast radius changes from 89 to 22.



\## Setup



Requirements: Python 3, Docker, AWS CLI, an AWS profile named `fulmen` with `IAMReadOnlyAccess` only.



```

pip install -r requirements.txt

docker run --rm -v trivy-cache:/root/.cache/ -v "${PWD}\\scan\_results:/output" aquasec/trivy image --timeout 15m --scanners vuln --severity HIGH,CRITICAL --format json --output /output/nginx-old.json nginx:1.19

python fetch\_iam\_roles.py

python correlate.py

```



Never commit AWS keys. Credentials stay in the AWS CLI profile, and `scan\_results/` is git-ignored.



\## Current limitations



\- The workload-to-role mapping is a manual file (`workloads.json`). A production version should discover it from ECS, EKS or EC2.

\- The what-if "image update" means applying all available package fixes, not only changing the image tag.

\- IAM analysis checks for wildcard actions. It does not yet calculate which resources a role can actually reach.

\- Only attached managed policies are analyzed, not inline policies.



\## Roadmap



\- Resource-level reach analysis (which S3 buckets a role can touch)

\- Scheduled engine loop with stored history

\- Dashboard UI

\- Automatic workload discovery



\## How this was built



I built this project with AI coding assistance while learning Python and cloud security. I reviewed and tested every part, and I can explain how each script works.

