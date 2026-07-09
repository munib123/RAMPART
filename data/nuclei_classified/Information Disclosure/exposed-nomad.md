# Nuclei Template: Nomad - Exposed Jobs
**Template ID:** exposed-nomad
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`nomad-jobs.yaml`)

## Vulnerability Information & PoC

## Description
Nomad jobs were discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ui/jobs
```

## References
- https://www.nomadproject.io/docs/internals/security
