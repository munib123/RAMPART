# Vulnerability: Polchat.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`polchatpl.yaml`)

## Description
Polchat.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://polczat.pl/forum/profile/{{user}}/
```

