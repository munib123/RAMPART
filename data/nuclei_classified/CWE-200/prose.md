# Vulnerability: Prose User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`prose.yaml`)

## Description
Prose user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://prose.astral.camp/{{user}}/
```

