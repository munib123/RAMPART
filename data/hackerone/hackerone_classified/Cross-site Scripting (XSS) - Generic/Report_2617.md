# HackerOne Report: Stored XSS in www.slack-files.com
**Report ID:** 2617
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

We can create posts under https://subdomain.slack.com/files/create/post

Post will have XSS payload like "><img src=x onerror=alert(10);> in title and body

We save it and hit "Create public link" and once we share the link it will trigger XSS.

Example/POC: https://slack-files.com/T025LLJ2X-F025N8W7W-3a5691

Thanks

Prakhar Prasad

## Discussion & Remediation Timeline
