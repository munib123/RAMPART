# Vulnerability: CirCarLife - Installer
**Classification:** CWE-284
**Source:** Nuclei Template (`circarlife-setup.yaml`)

## Description
A CirCarLife admin panel was accessed. CirCarLife is an internet-connected electric vehicle charging station

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/html/setup.html
```

