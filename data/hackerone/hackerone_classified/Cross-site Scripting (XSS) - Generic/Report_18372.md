# HackerOne Report: XSS
**Report ID:** 18372
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Dear Team,

Step-by-step instructions on how to reproduce the problem:

It was found the application is vulnerable to XSS attack.
To achieve the same,

open this link
http://staging.jsdelivr.net/g//%3Cimg/src=%22%3E%22+onerror=alert%28927942%29%3E

in firefox.

it can't prompt bcoz there is nothng just some code that's why it's can't prompt.
but when u write something there it will prompt.

Regard
Shubham Gupta

## Discussion & Remediation Timeline
