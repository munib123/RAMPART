# Vulnerability: Tanuki.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tanukipl.yaml`)

## Description
Tanuki.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tanuki.pl/profil/{{user}}
```

