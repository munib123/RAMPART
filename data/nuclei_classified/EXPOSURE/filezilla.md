# Vulnerability: Filezilla
**Classification:** EXPOSURE
**Source:** Nuclei Template (`filezilla.yaml`)

## Description
Filezilla internal file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/filezilla.xml
GET {{BaseURL}}/sitemanager.xml
GET {{BaseURL}}/FileZilla.xml
```

