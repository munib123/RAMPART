# HackerOne Report: XSS in experts.shopify.com
**Report ID:** 57459
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,
XSS vulnerability in experts.shopify.com,

Steps to verify:
1. Go  to https://experts.shopify.com
2. Sign up for an `expert`. (Please do note that you must create a new account if you already have, do not use existing account or an account that did not yet apply for an expert) then you will ask to login.
3. Fill up the necessary fields and upload photos.
4. Under `Portfolio Images` put `"><img src=x onerror=alert(document.domain)>` in the `caption` field.
5. Now hit `Save`, you will be redirected to page like this ( http://postimg.org/image/glodr1wj3/ )
6. Click one of the photos where the caption is `"><img src=x onerror=alert(document.domain)>`. XSS now executes.

Proof of concept: http://postimg.org/image/7jrwwaywn/

Please let me know if you need more information about this.

Regards,
Mr. Poo Gay

## Discussion & Remediation Timeline
