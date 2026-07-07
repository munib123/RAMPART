# HackerOne Report: mod_proxy_fcgi buffer overflow
**Report ID:** 36264
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
_This issue was reported directly to the Apache team._

A buffer overflow was found in mod_proxy_fcgi. A malicious FastCGI server could send a carefully crafted response which could lead to a heap buffer overflow.

http://httpd.apache.org/security/vulnerabilities_24.html#2.4.11-dev


## Discussion & Remediation Timeline
