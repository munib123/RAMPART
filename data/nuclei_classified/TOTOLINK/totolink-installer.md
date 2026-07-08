# Vulnerability: TOTOLINK Installer - Exposure
**Classification:** TOTOLINK
**Source:** Nuclei Template (`totolink-installer.yaml`)

## Description
Detects the presence of TOTOLINK router setup pages at /wizardset.htm and /easy_setup.htm.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wizardset.htm
GET {{BaseURL}}/easy_setup.htm
```

