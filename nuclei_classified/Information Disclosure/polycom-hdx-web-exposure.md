# Nuclei Template: Polycom HDX - Web Interface Exposure
**Template ID:** polycom-hdx-web-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-200
**Source:** Nuclei Template (`polycom-hdx-web-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detecetd Polycom HDX video conferencing system web interface, potentially allowing unauthorized access to device configuration and video calls.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

## References
- https://www.polycom.com/products-services/hd-telepresence-video-conferencing.html
- https://support.polycom.com/content/support/north-america/usa/en/support/video.html
