# Nuclei Template: Nexus Repository Manager - Anonymous Access Enabled
**Template ID:** nexus-repository-anonymous-access
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**Severity:** Medium
**CWE:** CWE-276
**Source:** Nuclei Template (`nexus-repository-anonymous-access.yaml`)

## Vulnerability Information & PoC

## Description
Detected Nexus Repository Manager instance with anonymous access enabled, allowing unauthenticated users to list and browse repositories containing private artifacts including source code, packages, and Docker images.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/service/rest/v1/repositories
```

## References
- https://help.sonatype.com/en/anonymous-access.html
- https://help.sonatype.com/en/access-control.html
