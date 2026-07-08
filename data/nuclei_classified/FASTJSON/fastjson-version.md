# Vulnerability: Fastjson Version Detection
**Classification:** FASTJSON
**Source:** Nuclei Template (`fastjson-version.yaml`)

## Description
If the server returns an exception to the client,The fastjson version will be retrieved,Fastjson versions greater than 1.2.41,Contains the latest version(1.2.76).

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"@type":"java.lang.AutoCloseable"
```

