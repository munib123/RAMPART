# Vulnerability: Fortnite Tracker User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortnite-tracker.yaml`)

## Description
Fortnite Tracker user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://fortnitetracker.com/profile/all/{{user}}
```

