# Vulnerability: Leantime - Unfinished Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`leantime-install-page-exposed.yaml`)

## Description
Detected a Leantime instance identified with the setup installation page accessible at /install, enabling unauthenticated users to create the first administrator account and configure the database.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

