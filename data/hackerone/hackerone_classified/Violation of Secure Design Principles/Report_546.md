# HackerOne Report: Logical issues with account settings
**Report ID:** 546
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
earlier email was not allowed to change ,but now there is no verification on changing email. when user try to change the password , they were asked to verify the request by entering old password. For the same reason a verification should be there on changing email.The worst part is hackone send verification mail on new mail id , and change the "join " date even on email change request.
 scenario: if some one left his account open on public computer(say office or cafe), then attacker can change the email ,verify it himself. Then abuse forgot password field to take over whole account.

Suggested mitigation: a password field can be applied(just like facebook do) or verification mail should be send on old email id registered. 

## Discussion & Remediation Timeline
