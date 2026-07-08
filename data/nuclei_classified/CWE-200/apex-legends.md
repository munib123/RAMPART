# Vulnerability: Apex Legends User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apex-legends.yaml`)

## Description
Apex Legends user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://apex.tracker.gg/apex/profile/origin/{{user}}/overview
```

