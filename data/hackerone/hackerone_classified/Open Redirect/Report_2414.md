# HackerOne Report: open redirect
**Report ID:** 2414
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
1. go to https://www.relateiq.com/sign-up
2. Fill the form and click on signup free button.
3. Intercept the request using tamper data and change the 'retURL' parameter to any value like https://google.com (any evil url) and submit the request.
4. The web app redirect to any evil website.

## Discussion & Remediation Timeline
