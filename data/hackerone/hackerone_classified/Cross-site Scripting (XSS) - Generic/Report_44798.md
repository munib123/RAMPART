# HackerOne Report: Vimeo Search - XSS Vulnerability [http://vimeo.com/search]
**Report ID:** 44798
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
I found a XSS vulnerability in Vimeo Search. Keeping it short so that it does not go duplicate.

Payload:  "onmouseover=alert(1)>

Live Demo: http://vimeo.com/search?q=%22onmouseover%3Dalert%281%29%3E

Search @ http://vimeo.com/search with above payload.

The culprit here is the Couch Mode feature.

After searching hover over broken couch mode link, alert should be triggered.

POC attached.

Special character are not encoded. We are able to break out of tag triggering XSS.

## Discussion & Remediation Timeline
