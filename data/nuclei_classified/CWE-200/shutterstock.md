# Vulnerability: Shutterstock User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`shutterstock.yaml`)

## Description
Shutterstock user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.shutterstock.com/g/{{user}}
```

