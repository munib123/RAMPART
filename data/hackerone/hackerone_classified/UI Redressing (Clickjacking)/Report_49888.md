# HackerOne Report: Missing X-Frame-Options header
**Report ID:** 49888
**Vulnerability Class:** UI Redressing (Clickjacking)

## Vulnerability Information & PoC
URL https://staging.seatme.us/

Vulnerability:
The server didn't return an X-Frame-Options header which means that this website could be at 
risk of a clickjacking attack. The X-Frame-Options HTTP response header can be used to indicate 
whether or not a browser should be allowed to render a page in a <frame> or <iframe>. 
Sites can use this to avoid clickjacking attacks, by ensuring that their content is not embedded 
into other sites.

Impact:
The impact depends on the affected web application.

Remedy:
Configure your web server to include an X-Frame-Options header.

Reference:
https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options

## Discussion & Remediation Timeline
