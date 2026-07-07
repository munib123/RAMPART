# HackerOne Report: Proxy service crash DoS
**Report ID:** 13652
**Vulnerability Class:** Uncontrolled Resource Consumption

## Vulnerability Information & PoC
Sending certain URLs to the proxy appears to crash the service, leading to a _502 Bad Gateway_ from nginx, presumably until the service is restarted. The following sequence sent in a short period appears to cause the crash (it could just be the _javascript:confirm()_ request, as the last request receives the 502, but I can't re-test to be sure):

http://staging.fct.li/?url=data:text/html,Hello
http://staging.fct.li/?url=data://text/html,Hello
http://staging.fct.li/?url=data://staging.fct.li/
http://staging.fct.li/?url=javascript:confirm()
http://staging.fct.li/?url=javascript:confirm("staging.fct.li")

## Discussion & Remediation Timeline
