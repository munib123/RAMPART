# HackerOne Report: Uses unsafe-inline without nonce 
**Report ID:** 96218
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
Hi,
I found you website using Uses unsafe-inline without nonce.
 Allowing unsafe-eval can increase risk of various types of attacks. Consider adding a nonce which makes injecting malicious code more difficult as an attacker would need to guess the nonce.
Thanks,

## Discussion & Remediation Timeline
