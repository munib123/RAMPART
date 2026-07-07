# HackerOne Report: Enumeration of users
**Report ID:** 761
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
As I can see, you prevent enumeration of users (actually e-mails of registered users) in Sign In (https://hackerone.com/users/sign_in) and Forgot password (https://hackerone.com/users/password/new) functionalities. However, the users can be enumerated in Sign Up (https://hackerone.com/users/sign_up) - just enter existing and non-existent e-mail addresses and see the responses. To prevent enumeration of users - ask the user in the first step to enter e-mail and tell him/her  that the next instructions will be sent to this mail to finish the registration process. When the mail is already registered - tell the user about it in the mail. When it is not registered, the user gets an unique URL in the mail to continue the registration process.

## Discussion & Remediation Timeline
