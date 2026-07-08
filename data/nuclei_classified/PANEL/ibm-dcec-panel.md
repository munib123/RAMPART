# Vulnerability: IBM Decision Center Enterprise Console - Panel Detection
**Classification:** PANEL
**Source:** Nuclei Template (`ibm-dcec-panel.yaml`)

## Description
IBM Decision Center Enterprise Console panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/teamserver/faces/login.jsp
```

