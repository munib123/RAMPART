# Vulnerability: Schneider TAC Vista - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`schneider-tac-vista-panel.yaml`)

## Description
Schneider TAC Vista building automation panel has been detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/webstation/
```

