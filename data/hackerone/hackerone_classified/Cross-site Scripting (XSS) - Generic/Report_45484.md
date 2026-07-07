# HackerOne Report: XSS on Vimeo
**Report ID:** 45484
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Poc video:
XSS on Vimeo: http://youtu.be/w5QgEEcMARY

1. Go to https://vimeo.com/settings/profile
2. Add a link with the payload on URL: javascript:alert(document.domain+"http://")
3. Click the link and payload will execute.

Thanks
@niyaax

## Discussion & Remediation Timeline
