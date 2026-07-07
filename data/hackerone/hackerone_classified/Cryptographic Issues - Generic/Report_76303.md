# HackerOne Report: weak ssl cipher suites
**Report ID:** 76303
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
> i found that some of the cipher suites are weak on you domain.
>
Here are those ( WEAK ):
DH 1024 bits (p: 128, g: 128, Ys: 128)   FS   WEAK
POC: https://www.ssllabs.com/ssltest/analyze.html?d=gratipay.com&s=23.23.184.160&latest

([original on Freshdesk](https://gratipay.freshdesk.com/helpdesk/tickets/2449))

## Discussion & Remediation Timeline
