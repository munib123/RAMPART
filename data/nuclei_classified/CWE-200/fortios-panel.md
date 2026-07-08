# Vulnerability: FortiOS Admin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortios-panel.yaml`)

## Description
FortiOS admin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v2/cmdb/system/admin/admin HTTP/1.1
Host: {{Hostname}}
```

