# Vulnerability: Editor Configuration File - Detect
**Classification:** CONFIG
**Source:** Nuclei Template (`editor-exposure.yaml`)

## Description
Editor configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.editorconfig
```

