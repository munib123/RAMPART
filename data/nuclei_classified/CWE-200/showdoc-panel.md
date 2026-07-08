# Vulnerability: ShowDoc Panel Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`showdoc-panel.yaml`)

## Description
ShowDoc panel was detected. ShowDoc was a tool for documenting APIs and interfaces.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/#/user/login
```

