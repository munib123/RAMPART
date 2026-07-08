# Vulnerability: Designspriation User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`designspriation.yaml`)

## Description
Designspriation user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.designspiration.com/{{user}}/
```

