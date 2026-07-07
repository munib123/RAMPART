# HackerOne Report: Timing Attack Side-Channel on API Token Verification
**Report ID:** 31167
**Vulnerability Class:** Cryptographic Issues - Generic

## Vulnerability Information & PoC
https://github.com/joola/joola/blob/develop/lib/dispatch/users.js#L514

Because tokens are compared with the `===` operator, this may be susceptible to timing attacks. More info: http://codahale.com/a-lesson-in-timing-attacks/

This is probably not the lowest hanging fruit for an attacker, but it's something you might want to fix. :)

Replacement utility: https://github.com/cryptocat/cryptocat/blob/32fd02f8d899e219a004281eb0ce364cb52dd62a/src/core/js/lib/otr.js#L145-L152

## Discussion & Remediation Timeline
