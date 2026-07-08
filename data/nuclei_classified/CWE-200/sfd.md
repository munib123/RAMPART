# Vulnerability: SFD User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sfd.yaml`)

## Description
SFD user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.sfd.pl/profile/{{user}}
```

