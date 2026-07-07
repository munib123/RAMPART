# HackerOne Report: No Cross-Site Request Forgery protection at multiple locations
**Report ID:** 7916
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
The Localize application does not provide protection against CSRF attacks at various locations. 
For example, the following actions/pages are vulnerable:

`POST /pages/create_project`
`POST /pages/settings`
`POST /add_phrase/$var/languages/$var`


See https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF) for more information.


## Discussion & Remediation Timeline
