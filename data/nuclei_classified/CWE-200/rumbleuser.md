# Vulnerability: RumbleUser User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rumbleuser.yaml`)

## Description
RumbleUser user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://rumble.com/user/{{user}}
```

