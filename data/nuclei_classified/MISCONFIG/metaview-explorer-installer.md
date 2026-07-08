# Vulnerability: MetaView Explorer Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`metaview-explorer-installer.yaml`)

## Description
MetaView Explorer is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

