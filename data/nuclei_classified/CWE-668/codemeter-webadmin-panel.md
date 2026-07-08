# Vulnerability: CodeMeter - WebAdmin Panel Access
**Classification:** CWE-668
**Source:** Nuclei Template (`codemeter-webadmin-panel.yaml`)

## Description
CodeMeter WebAdmin panel was accessed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

