# HackerOne Report: Criptographic Issue: Strisct Transport Security with not good max age..(TOO SHORT!)
**Report ID:** 15518
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
Issue: Strict Transport Security with too short max age.

Description: Your site use a good "Strict Transport Security" but with short MAX AGE!

Severity: See more information below.

Proof of Concept by ssllabs.com (100% affidability):

"Strict Transport Security (HSTS) Yes max-age=2592000 TOO SHORT (less than 180 days)

If you want to see the full scan with your "eyes" check it here: https://www.ssllabs.com/ssltest/analyze.html?d=staging.factlink.com&s=162.159.241.217

Also..See more information here:

https://community.qualys.com/thread/10857

Thanks and best regards,
Rockcena

## Discussion & Remediation Timeline
