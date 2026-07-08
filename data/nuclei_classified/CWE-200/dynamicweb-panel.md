# Vulnerability: Dynamicweb Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dynamicweb-panel.yaml`)

## Description
Dynamicweb login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /Admin/Access/default.aspx HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
```

