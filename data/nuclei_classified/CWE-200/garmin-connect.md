# Vulnerability: Garmin connect User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`garmin-connect.yaml`)

## Description
Garmin connect user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://connect.garmin.com/modern/profile/{{user}}
```

