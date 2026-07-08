# Vulnerability: Cloudflare Transform via URL - Image Injection
**Classification:** MISCONFIG
**Source:** Nuclei Template (`cloudflare-rocketloader-htmli.yaml`)

## Description
Transform via URL feature in Cloudflare allow attackers to show arbitrary images to the visitor of a crafted URL on the website. This can be used to perform various attacks such as phishing, defacement, etc.

## Secure Mitigation
Disable Images → Transformations → “Resize from any origin” setting in Cloudflare console.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cdn-cgi/image/width=1000,format=auto/https://raw.githubusercontent.com/simple-icons/simple-icons/develop/icons/cloudflare.svg
```

