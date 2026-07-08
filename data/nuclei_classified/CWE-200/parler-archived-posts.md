# Vulnerability: Parler archived posts User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`parler-archived-posts.yaml`)

## Description
Parler archived posts user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://archive.org/wayback/available?url=https://parler.com/profile/{{user}}/posts
```

