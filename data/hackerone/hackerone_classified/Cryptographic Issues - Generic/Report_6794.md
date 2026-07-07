# HackerOne Report: The server supports only older protocols for HTTPS connections
**Report ID:** 6794
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
The webserver at `c2fo.com`, `198.58.120.159` only supports SSL 3.0 and TLS 1.0 for secure HTTP connections (see: test-results.png). While TLS 1.0 is more secure than SSL 3.0, subsequent versions of TLS, TLS 1.1 and TLS 1.2, are significantly more secure and fix many vulnerabilities present in SSL 3.0 and TLS 1.0.

I recommend enabling support for TLS 1.1 and TLS 1.2.  Because not all browsers and operating systems support these new versions, to ensure availability, SSL 3.0 and/or TLS 1.0 should not be disabled (for now).

## Discussion & Remediation Timeline
