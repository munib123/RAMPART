# HackerOne Report: Open Redirection
**Report ID:** 12949
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Try to connect your facebook using this URL

http://www.urbandictionary.com/auth/facebook?origin=http://google.com

after connecting urbandictionary to FB you will be redirected to google.com

and that is bad because hackers can get the auth token

## Discussion & Remediation Timeline
