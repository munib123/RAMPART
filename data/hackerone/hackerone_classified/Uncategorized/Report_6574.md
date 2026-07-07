# HackerOne Report: Login page password-guessing attack
**Report ID:** 6574
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Hello team of Reddapi!

Here to report a vulnerability on your site.

Affected site: www.reddapi.com

Vulnerability: Login page password-guessing attack

Severity:Low.

Vulnerability description:

A brute-force attack is an attempt to discover a password by systematically trying every possible combination of letters, numbers, and symbols until you discover the one correct combination that works

Attack Details:

http://www.reddapi.com/ (/login) page doesn't have any protection against password-guessing attacks (brute force attacks). It's recommended to implement some type of account lockout after a defined number of incorrect password attempts.

I personally tried many times with wrong password even though no account lockout was detected.


Fix: Implement Captcha


Well, I wait more information about this report!


Thanks and best regards,


Simone

## Discussion & Remediation Timeline
