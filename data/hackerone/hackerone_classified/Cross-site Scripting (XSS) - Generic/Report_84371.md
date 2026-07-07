# HackerOne Report: apps.owncloud.com: Stored XSS in profile page
**Report ID:** 84371
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi Owncloud,

I've found  A XSS vulnerability on apps.owncloud.com

When I add a comment to add any comment field,My profile page shows my latest comment

When I add a comment starts with "><img src=x onerror=confirm(2)> the page show this comment 

so XSS alert occurs in profile page.

Even if a victim is not authenticated,vulnerability occurs on page



## Discussion & Remediation Timeline
