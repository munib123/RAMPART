# HackerOne Report: Password Reset - query param overrides postdata
**Report ID:** 96636
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
Suppose a user were to reset their password at the following url (with the given query parameters):
```
https://accounts.snapchat.com/accounts/change_password?
newpassword={someNewPass}&newpassword2={someNewPass}
```
Then regardless of the new password entered into the form, `{someNewPass}` becomes the user's new password.  This becomes malicious when an attacker refers a users to this url which contains these query parameters to change the user's password.

Even though this requires some level of social engineering -- convincing a user (whose username is known) not only to change his/her password, but do so via a given url -- I don't see a good reason to allow this behavior. Bottom line, _don't read username/passwords from query string_.

I look forward to your response.

## Discussion & Remediation Timeline
