# Vulnerability: Strava User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`strava.yaml`)

## Description
Strava user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.strava.com/athletes/{{user}}
```

