# Vulnerability: Microsoft AD CS Web Enrollment - Detect
**Classification:** AD
**Source:** Nuclei Template (`adcs-certificate.yaml`)

## Description
Detects Microsoft Active Directory Certificate Services (AD CS) Web Enrollment and certificate download pages.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/certenroll/
GET {{BaseURL}}/CertEnroll/
GET {{BaseURL}}/certsrv/
GET {{BaseURL}}/certsrv
```

