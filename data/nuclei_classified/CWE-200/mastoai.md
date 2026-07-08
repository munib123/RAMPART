# Vulnerability: Masto.ai User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastoai.yaml`)

## Description
Masto.ai user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://masto.ai/@{{user}}
```

