# Vulnerability: Fine art america User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fine-art-america.yaml`)

## Description
Fine art america user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://fineartamerica.com/profiles/{{user}}
```

