# Vulnerability: Filestash Admin Password Configuration
**Classification:** EXPOSURE
**Source:** Nuclei Template (`filestash-admin-config.yaml`)

## Description
Filestash is susceptible to the Admin Password Configuration page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/setup
```

