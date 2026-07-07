# HackerOne Report: CVE-2014-0224 openssl ccs vulnerability
**Report ID:** 50885
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
your site is vulnerable to CVE-2014-0224
 

OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive information, via a crafted TLS handshake, aka the "CCS Injection" vulnerability.

## Discussion & Remediation Timeline
