# HackerOne Report: Xss in website's link
**Report ID:** 54321
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

I found Xss in my website's link.

Steps:

Go to this page https://app.shopify.com/services/partners/account/edit
In fileld "Website (optional)" add javascript:alert(document.cookie);//http://dgddfgdfgg.ua
and save

Need registration https://experts.shopify.com/signup

After we can see account. Click link website

## Discussion & Remediation Timeline
