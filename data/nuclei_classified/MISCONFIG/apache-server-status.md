# Vulnerability: Apache Server Status Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`apache-server-status.yaml`)

## Description
Apache /server-status displays information about your Apache status. If you are not using this feature, disable it.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/server-info
GET {{BaseURL}}/server-status
```

