# Vulnerability: Tenda 11n Wireless Router - Admin Panel
**Classification:** CWE-668
**Source:** Nuclei Template (`tenda-11n-wireless-router-login.yaml`)

## Description
The administrative panel for a Tenda Technology 11n Wireless Router was found.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.asp
```

