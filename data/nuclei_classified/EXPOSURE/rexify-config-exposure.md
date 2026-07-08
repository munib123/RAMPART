# Vulnerability: Rexify Configuration - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`rexify-config-exposure.yaml`)

## Description
Rexfile configuration from the Rex/Rexify automation framework was exposed. These files may contain SSH credentials, server hostnames, private key paths, and other sensitive data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Rexfile
```

