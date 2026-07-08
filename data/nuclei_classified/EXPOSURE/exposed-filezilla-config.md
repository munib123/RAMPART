# Vulnerability: Exposed FileZilla Configuration File - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`exposed-filezilla-config.yaml`)

## Description
Detected publicly accessible FileZilla client configuration files (sitemanager.xml, recentservers.xml, filezilla.xml).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/files/FileZilla.xml
GET {{BaseURL}}/recentservers.xml
GET {{BaseURL}}/filezilla.xml
```

