# HackerOne Report: Login page password-guessing attack
**Report ID:** 110
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
A brute-force attack is an attempt to discover a password by systematically trying every possible combination of letters, numbers, and symbols until you discover the one correct combination that works. 

hackerone.com page doesn't have any protection against password-guessing attacks (brute force attacks). It's recommended to implement some type of account lockout after a defined number of incorrect password attempts.

I personally tried many times with wrong password even though no account lockout was detected.

Fix : Implement captcha  


## Discussion & Remediation Timeline
