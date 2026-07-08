# Vulnerability: Arduino User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`arduino.yaml`)

## Description
Arduino user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://create.arduino.cc/projecthub/{{user}}
```

