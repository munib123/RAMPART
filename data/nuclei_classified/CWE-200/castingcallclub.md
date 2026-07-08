# Vulnerability: CastingCallClub User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`castingcallclub.yaml`)

## Description
CastingCallClub user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.castingcall.club/{{user}}
```

