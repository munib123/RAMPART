# Vulnerability: AVEVA InTouch Access Anywhere - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`aveva-intouch-access-anywhere-panel.yaml`)

## Description
Detected AVEVA InTouch Access Anywhere was a secure gateway that provided browser-based remote access to InTouch HMI applications over the internet. It was widely used in industrial process control, utilities, and manufacturing environments. Exposed instances may have provided access to industrial HMI displays and SCADA interfaces.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/AccessAnywhere/start.html
```

