# HackerOne Report: harvesting attack on user registration
**Report ID:** 2193
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
url: https://hackerone.com/users/sign_up

user account registration will ask for the applicant to provide all of the information required to create an account on a registration page. When the registration page is submitted, the application validates the uniqueness of the username and email address. The application then responds with
1.Username has already been taken
2. Email has already been taken

This behavior can be leveraged to harvest valid users of the application by attempting to register accounts with suspected usernames and emails and analyzing the responses.


## Discussion & Remediation Timeline
