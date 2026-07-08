# Vulnerability: Imgproxy Unauthorized Access
**Classification:** IMGPROXY
**Source:** Nuclei Template (`imgproxy-unauth.yaml`)

## Description
imgproxy is a fast and secure standalone server for resizing, processing, and converting images.

## Secure Mitigation
set IMGPROXY_SECRET environment variable.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_/resize:fill:10:10:0/gravity:sm/plain/{{img_url}}
```

