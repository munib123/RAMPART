# Vulnerability: Zhiyuan OA Arbitrary File Upload Vulnerability
**Classification:** ZHIYUAN
**Source:** Nuclei Template (`zhiyuan-file-upload.yaml`)

## Description
A vulnerability in Zhiyuan OA allows remote unauthenticated attackers to upload arbitrary files to the remote server and cause execute arbitrary code to be executed.

## Secure Mitigation
Apply the appropriate patch.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/seeyon/thirdpartyController.do.css/..;/ajax.do
```

