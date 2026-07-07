# HackerOne Report: Malformed ECParameters causes infinite loop
**Report ID:** 73241
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Malformed ECParameters causes infinite loop (CVE-2015-1788)
===========================================================

Severity: Moderate

When processing an ECParameters structure OpenSSL enters an infinite loop if the curve specified is over a specially malformed binary polynomial field.

This can be used to perform denial of service against any system which processes public keys, certificate requests or certificates.  This includes TLS clients and TLS servers with client authentication enabled.

This issue affects OpenSSL versions: 1.0.2 and 1.0.1. Recent 1.0.0 and 0.9.8 versions are not affected. 1.0.0d and 0.9.8r and below are affected.

OpenSSL 1.0.2 users should upgrade to 1.0.2b
OpenSSL 1.0.1 users should upgrade to 1.0.1n
OpenSSL 1.0.0d (and below) users should upgrade to 1.0.0s
OpenSSL 0.9.8r (and below) users should upgrade to 0.9.8zg

This issue was reported to OpenSSL on 6th April 2015 by Joseph Birr-Pixton. The fix was developed by Andy Polyakov of the OpenSSL development team.

http://jbp.io/2015/06/11/cve-2015-1788-openssl-binpoly-hang/

## Discussion & Remediation Timeline
