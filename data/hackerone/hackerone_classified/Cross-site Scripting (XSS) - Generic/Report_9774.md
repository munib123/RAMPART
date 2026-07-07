# HackerOne Report: Stored XSS Found
**Report ID:** 9774
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
The type of XSS Vulnerability I found on your website is a stored xss. after i connect my github account   and add a new integration then i chose my repositories then on the right side of that is a textfield that has a placeholder of  Branches (optional). then i put the following code on that textfield "><img src=x onerror=alert(document.domain);>  then i click save integration button. then after that an alert box popup containing the domain of the site.

## Discussion & Remediation Timeline
