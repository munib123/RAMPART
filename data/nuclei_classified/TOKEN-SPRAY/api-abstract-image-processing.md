# Vulnerability: Abstract Api Image Processing Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-image-processing.yaml`)

## Description
Manage your images programmatically with this powerful API compress, convert, crop, resize, and more.

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://images.abstractapi.com/v1/url/ HTTP/1.1
Host: images.abstractapi.com
Content-Type: application/json
Accept: application/json

{"api_key": "{{token}}", "lossy": true, "url": "https://s3.amazonaws.com/static.abstractapi.com/test-images/dog.jpg"}
```

