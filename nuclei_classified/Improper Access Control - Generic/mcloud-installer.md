# Nuclei Template: mCloud Panel - Installer
**Template ID:** mcloud-installer
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`mcloud-installer.yaml`)

## Vulnerability Information & PoC

## Description
mCloud installer was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/clusterList
```

## References
- https://mcloudcorp.com/
