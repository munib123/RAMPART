# Vulnerability: RumbleChannel User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rumblechannel.yaml`)

## Description
RumbleChannel user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://rumble.com/c/{{user}}
```

