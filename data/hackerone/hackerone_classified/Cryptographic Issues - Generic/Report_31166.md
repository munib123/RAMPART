# HackerOne Report: Weak Random Number Generator for Auth Tokens
**Report ID:** 31166
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
https://github.com/joola/joola/blob/a534c3dca1a0deaec99c192978e61a35dd3a9069/lib/common/index.js#L90-L98

`Math.random()` is not sufficient for cryptographic purposes (such as authentication tokens).

An example replacement that uses `window.crypto.getRandomValues()` is available here:

https://github.com/resonantcore/lib/blob/9362480647b304aee6819ea94a18409241e79378/js/diceware/diceware.js#L60-L94

Further information:
https://media.blackhat.com/us-13/US-13-Soeder-Black-Box-Assessment-of-Pseudorandom-Algorithms-WP.pdf

## Discussion & Remediation Timeline
