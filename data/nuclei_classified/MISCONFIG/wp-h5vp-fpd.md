# Vulnerability: WordPress H5VP Plugin - Full Path Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`wp-h5vp-fpd.yaml`)

## Description
The WordPress H5VP video plugin diclosed full server paths in stack traces when processing video requests.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-json/h5vp/v1/video HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"title":"{{name}}","type":"youtube","src":"{{name}}","user_id":"1"}
```

