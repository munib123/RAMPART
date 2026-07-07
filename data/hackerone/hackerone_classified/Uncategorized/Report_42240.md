# HackerOne Report: chrome allows POST requests with custom headers using flash + 307 redirect
**Report ID:** 42240
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hi,

well, It was reported directly to google(as It affected specially chrome) https://code.google.com/p/chromium/issues/detail?id=332023 . This vulnerability allowed post request with custom headers be sent to any websites(not respecting same origin policy) which chrome was mainly affected. Don't know if adobe made any code change due to this report and either if this program covers this kind of vulnerabilities, but i'm reporting it anyway.

wonder if this could be eligible for bug bounty ? 

## Discussion & Remediation Timeline
