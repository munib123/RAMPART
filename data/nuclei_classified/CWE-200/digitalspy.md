# Vulnerability: Digitalspy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`digitalspy.yaml`)

## Description
Digitalspy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forums.digitalspy.com/profile/discussions/{{user}}
```

