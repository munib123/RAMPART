# Vulnerability: Huawei HG532e Router Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`huawei-hg532e-panel.yaml`)

## Description
Huawei HG532e router login panel was detected. After installation, both the default username and default password are user.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

