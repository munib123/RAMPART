# Vulnerability: Twitter archived tweets User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`twitter-archived-tweets.yaml`)

## Description
Twitter archived tweets user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://archive.org/wayback/available?url=https://twitter.com/{{user}}/status/*
```

