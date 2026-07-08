# Vulnerability: McAfee ePolicy Orchestrator - Arbitrary File Upload
**Classification:** MCAFEE
**Source:** Nuclei Template (`mcafee-epo-rce.yaml`)

## Description
McAfee ePolicy Orchestrator (ePO) is vulnerable to a ZipSlip vulnerability which allows arbitrary file upload when archives are unpacked if the names of the packed files are not properly sanitized. An attacker can create archives with files containing "../" in their names, making it possible to upload arbitrary files to arbitrary directories or overwrite existing ones during archive extraction.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/stat.jsp?cmd=chcp+437+%7c+dir
```

