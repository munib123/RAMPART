# Vulnerability: CTFLearn User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ctflearn.yaml`)

## Description
CTFLearn user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ctflearn.com/user/{{user}}
```

