# Vulnerability: Tripadvisor User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tripadvisor.yaml`)

## Description
Tripadvisor user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.tripadvisor.com/Profile/{{user}}
```

