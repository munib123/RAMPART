# HackerOne Report: Html injection on khanacademy
**Report ID:** 83604
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
There's an HTML Injection Vulnerability exists in khanacademy .
 Affected parameters "linkSuccess="


Steps to reproduce:
1. first open your account on khanacademy.
2.enter the link in the url box.
   http://khanacademy.org/settings/account?linkSuccess=
3.set any text after "=" (eg.  http://khanacademy.org/settings/account?linkSuccess=hello world)
4.hit enter .
5 you see......

i have attach a poc video in this report.


## Discussion & Remediation Timeline
