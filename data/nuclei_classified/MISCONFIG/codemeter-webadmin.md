# Vulnerability: CodeMeter Webadmin Dashboard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`codemeter-webadmin.yaml`)

## Description
CodeMeter Webadmin Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.html
```

