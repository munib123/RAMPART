# Vulnerability: Sentimente User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sentimente.yaml`)

## Description
Sentimente user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.sentimente.com/amp/{{user}}.html
```

