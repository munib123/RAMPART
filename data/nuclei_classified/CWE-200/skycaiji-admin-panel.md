# Vulnerability: SkyCaiji Admin Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`skycaiji-admin-panel.yaml`)

## Description
SkyCaiji admin panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=/admin/Index/index
```

