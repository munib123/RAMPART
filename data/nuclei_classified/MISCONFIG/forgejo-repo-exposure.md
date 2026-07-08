# Vulnerability: Forgejo Repositories - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`forgejo-repo-exposure.yaml`)

## Description
The Forgejo repo is being exposed publically.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/explore/repos
```

