# Vulnerability: Newmeet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`newmeet.yaml`)

## Description
Newmeet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.newmeet.com/en/profile/{{user}}
```

