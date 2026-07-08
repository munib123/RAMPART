# Vulnerability: Nexus Repository Manager - Anonymous Access Enabled
**Classification:** CWE-276
**Source:** Nuclei Template (`nexus-repository-anonymous-access.yaml`)

## Description
Detected Nexus Repository Manager instance with anonymous access enabled, allowing unauthenticated users to list and browse repositories containing private artifacts including source code, packages, and Docker images.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/service/rest/v1/repositories
```

