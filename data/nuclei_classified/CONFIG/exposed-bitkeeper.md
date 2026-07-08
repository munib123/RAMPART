# Vulnerability: BitKeeper Configuration - Detect
**Classification:** CONFIG
**Source:** Nuclei Template (`exposed-bitkeeper.yaml`)

## Description
BitKeeper configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/BitKeeper/etc/config
```

