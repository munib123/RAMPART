# HackerOne Report: Pretty Photo Dom XSS 
**Report ID:** 62385
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi Team,

Javascript for http://www.jsdelivr.com/#!prettyphoto hosted on the website points to 3.1.5 which is vulnerable to DOMXSS the upstream released an update 3.1.6 7 days back still the CDN is serving vulnerable edition effectively making all the websites vulnerable to DoMXSS

Details about the issue are outlined : http://blog.anantshri.info/forgotten_disclosure_dom_xss_prettyphoto

github issue for the stuff : https://github.com/scaron/prettyphoto/issues/149

Hope this helps.

## Discussion & Remediation Timeline
