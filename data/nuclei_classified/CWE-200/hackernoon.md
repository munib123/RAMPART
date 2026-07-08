# Vulnerability: Hackernoon User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hackernoon.yaml`)

## Description
Hackernoon user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hackernoon.com/_next/data/foL6JC7ro2FEEMD-gMKgQ/u/{{user}}.json
```

