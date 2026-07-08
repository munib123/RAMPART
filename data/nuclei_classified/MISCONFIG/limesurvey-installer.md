# Vulnerability: Limesurvey Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`limesurvey-installer.yaml`)

## Description
Limesurvey is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?r=installer/welcome
```

