# Vulnerability: Atlassian Bitbucket Public Repository Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`bitbucket-public-repository.yaml`)

## Description
Bitbucket Public Repository is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/repos?visibility=public
GET {{BaseURL}}/bitbucket/repos?visibility=public
```

