# Vulnerability: CodeChef User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`codechef.yaml`)

## Description
CodeChef user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.codechef.com/users/{{user}}
```

