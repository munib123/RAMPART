# Vulnerability: Sukebei.nyaa.si User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sukebeinyaasi.yaml`)

## Description
Sukebei.nyaa.si user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://sukebei.nyaa.si/user/{{user}}
```

