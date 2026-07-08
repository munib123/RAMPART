# Vulnerability: FusionAuth Exposed Admin Setup
**Classification:** MISCONFIG
**Source:** Nuclei Template (`fusionauth-admin-setup.yaml`)

## Description
FusionAuth Admin Setup is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/setup-wizard
```

