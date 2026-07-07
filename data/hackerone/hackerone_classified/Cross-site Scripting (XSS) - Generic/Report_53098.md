# HackerOne Report: XSS in twitter.com/safety/unsafe_link_warning
**Report ID:** 53098
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
The following page has XSS.
https://twitter.com/safety/unsafe_link_warning?unsafe_link=[vulnerable_param]

Steps to reproduce: 
1. Go to the following URL using IE: 
https://twitter.com/safety/unsafe_link_warning?unsafe_link=https%3A%2F%2Ftwitter.com%2Fsafety%2Funsafe_link_warning%3Funsafe_link%3Dhttp%3A%2F%2Fexample.com%2520onmouseover%3Dalert%281%29%2520style=font-size:100pt%2520

2. Click "continue".

3.  Do mouseover to "continue". XSS occurs.

FYI in Firefox and Chrome, it is blocked by CSP :)

I recommend fixing this.
Thanks!

## Discussion & Remediation Timeline
