# Vulnerability: Opencollective User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opencollective.yaml`)

## Description
Opencollective user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://opencollective.com/{{user}}
```

