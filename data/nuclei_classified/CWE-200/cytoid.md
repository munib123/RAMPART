# Vulnerability: Cytoid User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cytoid.yaml`)

## Description
Cytoid user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cytoid.io/profile/{{user}}
```

