# Vulnerability: GeniusOcean Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`geniusocean-installer.yaml`)

## Description
GeniusOcean is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/?step=1
```

