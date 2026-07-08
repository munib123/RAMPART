# Vulnerability: cheat.sh Instance - Detection
**Classification:** TECH
**Source:** Nuclei Template (`cheatsh-detect.yaml`)

## Description
Detects exposed cheat.sh instances. cheat.sh is a community-driven cheat sheet service that provides quick command-line reference for programming languages and Unix commands. While designed to be public, self-hosted instances may expose internal documentation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

