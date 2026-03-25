# EP Customer Context for Vulnerability Analysis

## Environment
- All workloads run as containers on Amazon EKS (non-prod currently)
- Containers share the host kernel — kernel CVEs in container base images are NOT exploitable
- Small SRE team (Dan Dunham, Tyler Roach, Alexander) — cannot manually triage hundreds of CVEs
- Small security team (Ashley Greenberg) — comes from Qualys background, expects validated actionable findings
- Dev teams are separate from SRE — app dependency vulns (npm, Java) need JIRA tickets routed to dev teams
- SRE handles infra: base images, container runtimes, K8s node upgrades

## What matters to EP
- Vulnerabilities that are actually exploitable in their container environment
- Clear fix instructions (what to update, who should do it)
- Don't flood teams with noise they can't act on

## What doesn't matter
- Kernel CVEs on container images (containers use host kernel)
- Disputed CVEs with no practical exploit
- OS packages in base images that have no fix available AND are low severity
- Secrets detected in npm internal files (corepack keys, test fixtures) — these are not real secrets
