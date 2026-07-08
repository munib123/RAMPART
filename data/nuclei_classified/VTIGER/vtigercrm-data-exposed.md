# Vulnerability: Vtiger CRM - Exposed Directory
**Classification:** VTIGER
**Source:** Nuclei Template (`vtigercrm-data-exposed.yaml`)

## Description
Detected a Vtiger CRM directory listing exposure that could have revealed sensitive files and internal application structure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{exposed_path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

