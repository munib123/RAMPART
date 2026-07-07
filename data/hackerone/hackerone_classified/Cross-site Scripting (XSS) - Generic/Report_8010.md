# HackerOne Report: XSS via Email Link
**Report ID:** 8010
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hey,

So, we can send emails to team email address like  - **kfvm@mail.respond.ly** . In the email body if there is a hyperlink pointing to `javascript:alert(0);` or any other `javascript: URI` then open viewing the email in your web application with *original HTML* view and then on clicking it will trigger javascript execution, that is XSS.

Thanks!

## Discussion & Remediation Timeline
