# Vulnerability: My instants User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`my-instants.yaml`)

## Description
My instants user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.myinstants.com/en/profile/{{user}}/
```

