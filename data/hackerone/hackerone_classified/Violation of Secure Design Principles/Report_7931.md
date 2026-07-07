# HackerOne Report: Issue with remember_user_token
**Report ID:** 7931
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
When a user logs out, cookie named remember_user_token is invalidated on the user side. When the user log in again with functionality 'remember me for a week', he gets the same value of  remember_user_token as previously. 

Moreover, when there is only cookie named remember_user_token in request, the user gets the same value of remember_user_token in forthcoming response.

As it can be seen in the aforementioned cases, remember_user_token is not regenerated, what constitutes a weakness in lifecycle of this cookie.

## Discussion & Remediation Timeline
