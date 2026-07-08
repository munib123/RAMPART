# Vulnerability: Duolingo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`duolingo.yaml`)

## Description
Duolingo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.duolingo.com/2017-06-30/users?username={{user}}&_=1628308619574
```

