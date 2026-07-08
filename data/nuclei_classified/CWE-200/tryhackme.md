# Vulnerability: TryHackMe User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tryhackme.yaml`)

## Description
TryHackMe user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tryhackme.com/p/{{user}}
```

