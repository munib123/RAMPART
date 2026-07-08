# Vulnerability: Opencast Admin Panel Discovery
**Classification:** PANEL
**Source:** Nuclei Template (`opencast-detect.yaml`)

## Description
An Opencast Admin panel was discovered. Opencast is a free and open source solution for automated video capture and distribution at scale.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin-ng/login.html
```

