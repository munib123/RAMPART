# Vulnerability: Cisco Webex Meetings - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`cisco-webex-meetings-detect.yaml`)

## Description
Detects Cisco Webex Meetings panel by requesting the modern Webex dashboard and matching unique Webex HTML markers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

