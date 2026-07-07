# HackerOne Report: Possible SQL injection on "Jump to twitter"
**Report ID:** 81701
**Vulnerability Class:** SQL Injection

## Vulnerability Information & PoC
The https://gratipay.com/on/twitter/'  (single-quote at the end) request returns 500 Error, but https://gratipay.com/on/twitter/" returns 404 so i believe it may be an injection. To find the url, go to /search and jump to ' twitter.

## Discussion & Remediation Timeline
