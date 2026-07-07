# HackerOne Report: Reflected Self-XSS in Slack
**Report ID:** 97683
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
1. Go to https://(domainname).slack.com/services/new
2. In the searchbar, type an XSS payload (I used <img src=x onerror=alert(document.domain)>)
3. Hit Enter
4. XSS pop-up

Thanks!

I have provided POCs

## Discussion & Remediation Timeline
