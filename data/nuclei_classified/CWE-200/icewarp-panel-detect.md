# Vulnerability: IceWarp Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`icewarp-panel-detect.yaml`)

## Description
IceWarp login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webmail/
```

