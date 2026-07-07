# HackerOne Report: Business logic Failure - Browser cache management and logout vulnerability.
**Report ID:** 7909
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Vulnerability class: Business logic Failure - Browser cache management and logout vulnerability.

Vulnerability impact: Logging out from an application does not clear the browser cache of any sensitive information that have been stored.

Steps to reproduce: 1. Login to portal. 2.browse few tabs 3. Click Logout 4. Click browser back button 5. you should able to see previous page and not only previous page but also viewed pages in the portal by clicking back back button

Thanks
Hari

## Discussion & Remediation Timeline
