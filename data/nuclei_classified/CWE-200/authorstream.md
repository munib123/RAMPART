# Vulnerability: AuthorSTREAM User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`authorstream.yaml`)

## Description
AuthorSTREAM user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://www.authorstream.com/{{user}}/
```

