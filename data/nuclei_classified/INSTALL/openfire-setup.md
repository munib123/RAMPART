# Vulnerability: Openfire Setup - Exposure
**Classification:** INSTALL
**Source:** Nuclei Template (`openfire-setup.yaml`)

## Description
Checks for the presence of a Openfire Setup Page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/index.jsp
```

