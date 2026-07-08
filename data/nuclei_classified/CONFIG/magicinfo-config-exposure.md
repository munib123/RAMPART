# Vulnerability: Samsung MagicINFO Configuration File
**Classification:** CONFIG
**Source:** Nuclei Template (`magicinfo-config-exposure.yaml`)

## Description
Detects exposure of Samsung MagicINFO configuration file (/MagicInfo/config.js),and extracts magicInfoFrontEndVersion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/MagicInfo/config.js
```

