# Vulnerability: StackOverflow User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`stackoverflow.yaml`)

## Description
StackOverflow user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://stackoverflow.com/users/filter?search={{user}}
```

