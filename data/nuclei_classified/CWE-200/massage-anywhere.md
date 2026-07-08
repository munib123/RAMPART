# Vulnerability: Massage Anywhere User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`massage-anywhere.yaml`)

## Description
Massage Anywhere user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.massageanywhere.com/profile/{{user}}
```

