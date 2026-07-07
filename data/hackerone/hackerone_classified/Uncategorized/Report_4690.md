# HackerOne Report: SPDY heap buffer overflow
**Report ID:** 4690
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
A bug in the experimental SPDY implementation in nginx was found, which might allow an attacker to cause a heap memory buffer overflow in a worker process by using a specially crafted request, potentially resulting in arbitrary code execution (CVE-2014-0133).

The problem affects nginx 1.3.15 - 1.5.11, compiled with the ngx_http_spdy_module module (which is not compiled by default) and without --with-debug configure option, if the "spdy" option of the "listen" directive is used in a configuration file.

The problem is fixed in nginx 1.5.12, 1.4.7.

Patch for the problem can be found here:

http://nginx.org/download/patch.2014.spdy2.txt

Thanks to Lucas Molas, researcher at Programa STIC, Fundación Dr. Manuel Sadosky, Buenos Aires, Argentina.


## Discussion & Remediation Timeline
