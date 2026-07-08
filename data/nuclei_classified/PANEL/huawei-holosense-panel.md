# Vulnerability: Huawei HoloSens SDC - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`huawei-holosense-panel.yaml`)

## Description
Huawei HoloSens SDC Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
POST {{BaseURL}}/cgi-bin/main.cgi
POST {{BaseURL}}/cgi-bin/main.cgi
```

