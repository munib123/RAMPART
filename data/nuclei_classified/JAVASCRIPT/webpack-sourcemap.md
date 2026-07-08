# Vulnerability: Webpack Sourcemap
**Classification:** JAVASCRIPT
**Source:** Nuclei Template (`webpack-sourcemap.yaml`)

## Description
Detects if Webpack source maps are exposed.

## Secure Mitigation
Ensure that Webpack source maps are not exposed to the public by configuring the server to restrict access to them.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{scripturi}}
GET {{scripturi}}
GET {{scripturi}}
GET {{mapuri}}
GET {{replace_regex(scripturi,"([^/]+$)","")}}{{replace_regex(mapuri,"(^\/+)","")}}
GET {{replace_regex(scripturi,replace_regex(scripturi,"http.+//[^/]+",""),"")}}{{mapuri}}
GET {{Scheme}}{{mapuri}}
```

