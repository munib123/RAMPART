# Nuclei Template: Oracle E-Business System Credentials Page - Detect
**Template ID:** oracle-ebs-credentials
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`oracle-ebs-credentials.yaml`)

## Vulnerability Information & PoC

## Description
Oracle E-Business System credentials page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/OA_HTML/jtfwrepo.xml
```

## References
- https://www.blackhat.com/docs/us-16/materials/us-16-Litchfield-Hackproofing-Oracle-eBusiness-Suite-wp-4.pdf
- https://www.blackhat.com/docs/us-16/materials/us-16-Litchfield-Hackproofing-Oracle-eBusiness-Suite.pdf
- http://www.davidlitchfield.com/AssessingOraclee-BusinessSuite11i.pdf
