# Vulnerability: Nomad - Exposed Jobs
**Classification:** CWE-200
**Source:** Nuclei Template (`nomad-jobs.yaml`)

## Description
Nomad jobs were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/jobs
```

