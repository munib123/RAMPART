# Vulnerability: Marshmallow User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`marshmallow.yaml`)

## Description
Marshmallow user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://marshmallow-qa.com/{{user}}
```

