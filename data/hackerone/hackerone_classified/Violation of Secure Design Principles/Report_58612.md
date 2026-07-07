# HackerOne Report: Homograph attack
**Report ID:** 58612
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hello!

I would like to report that fix of report #29491 is incomplete. There is another way to reproduce homograph attack: <http:ebаy.com> or <http:/ebаy.com>

IDNs are displayed in unicode and there is no encoding into Punycode on external link warning page

Thanks!

\- Matvejs

## Discussion & Remediation Timeline
