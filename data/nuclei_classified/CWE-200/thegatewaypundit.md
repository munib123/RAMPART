# Vulnerability: Thegatewaypundit User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`thegatewaypundit.yaml`)

## Description
Thegatewaypundit user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.thegatewaypundit.com/author/{{user}}/
```

