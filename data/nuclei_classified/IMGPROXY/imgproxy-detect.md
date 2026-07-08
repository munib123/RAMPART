# Vulnerability: Imgproxy Detect
**Classification:** IMGPROXY
**Source:** Nuclei Template (`imgproxy-detect.yaml`)

## Description
imgproxy is a fast and secure standalone server for resizing, processing, and converting images.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

