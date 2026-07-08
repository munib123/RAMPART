# Vulnerability: Nnru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nnru.yaml`)

## Description
Nnru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.www.nn.ru
```

