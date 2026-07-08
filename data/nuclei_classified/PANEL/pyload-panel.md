# Vulnerability: PyLoad Login - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`pyload-panel.yaml`)

## Description
A Pyload Login was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login
```

