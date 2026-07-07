# HackerOne Report: Sign-up Form CSRF
**Report ID:** 7865
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Cross-site request forgery, also known as a one-click attack or session riding and abbreviated as CSRF or XSRF, is a type of malicious exploit of a website whereby unauthorized commands are transmitted from a user that the website trusts.


Form action: http://www.localize.io/pages/sign_up
Form method: POST

Form inputs:

sign_up[type] [Radio]
sign_up[username] [Text]
sign_up[password1] [Password]
sign_up[password2] [Password]


The impact of this vulnerability:-

An attacker may force the users of a web application to execute actions of the attacker's choosing. A successful CSRF exploit can compromise end user data and operation in case of normal user. If the targeted end user is the administrator account, this can compromise the entire web application.

How to fix this vulnerability:-

Check if this form requires CSRF protection and implement CSRF countermeasures if necessary.


## Discussion & Remediation Timeline
