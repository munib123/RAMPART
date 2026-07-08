# Vulnerability: Slurm HPC Dashboard - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`slurm-hpc-dashboard.yaml`)

## Description
Slurm HPC Dashboard was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/slurm/
```

