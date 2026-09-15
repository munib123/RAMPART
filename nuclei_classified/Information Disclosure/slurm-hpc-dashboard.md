# Nuclei Template: Slurm HPC Dashboard - Detect
**Template ID:** slurm-hpc-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`slurm-hpc-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Slurm HPC Dashboard was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/slurm/
```

## References
- https://grafana.com/grafana/dashboards/4323-slurm-dashboard/
