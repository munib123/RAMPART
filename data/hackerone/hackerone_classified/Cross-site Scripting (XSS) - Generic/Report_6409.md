# HackerOne Report: https://www.khanacademy.org/coach/reports/activity XSS
**Report ID:** 6409
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

I created a class called `"><img src=x onerror=alert(4)>`, I hope that you know how to make a class..
After that, when you go to https://www.khanacademy.org/coach/reports/activity and select a class it might not load directly but when you reloud the page it will (and persistent).

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
