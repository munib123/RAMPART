# Vulnerability: Gravatar User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gravatar.yaml`)

## Description
Gravatar user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://en.gravatar.com/profiles/{{user}}.json
```

