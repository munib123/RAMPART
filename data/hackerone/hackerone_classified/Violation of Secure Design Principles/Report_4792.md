# HackerOne Report: HttpOnly flag not set for cookie on concrete5.org
**Report ID:** 4792
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hi,

The HttpOnly flag is not set on concrete5.org, making it easy to steal the cookie when a XSS is present on the site.

See [HttpOnly on OWASP](https://www.owasp.org/index.php/HttpOnly) for more information.



## Discussion & Remediation Timeline
