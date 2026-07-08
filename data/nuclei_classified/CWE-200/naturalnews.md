# Vulnerability: NaturalNews User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`naturalnews.yaml`)

## Description
NaturalNews user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://naturalnews.com/author/{{user}}/
```

