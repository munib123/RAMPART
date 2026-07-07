# HackerOne Report: Email Verification Link can be Used as Password Reset Link!
**Report ID:** 98469
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hello again!

basically,I have found a new issue which allows attacker to use a Email Verification Link and make it into a password reset link!

Proof Of Concept:
When you Send a Email Verification Link
It looks like this "https://www.binary.com/user/validate_link?step=account&verify_token=q4b4QVyLZD9daVpAdiXAIiAExC8DaGmqFPk8wNt9nTqAm7Pa&l=EN"

Remove "step=account" from the URL, and tadaa! you will see once u enter the email you can change password!

Thank you,
-Karim

## Discussion & Remediation Timeline
