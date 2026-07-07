# HackerOne Report: Control character allowed in username
**Report ID:** 3921
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
It turns out, that it is possible to register a user with a special sign %0a (appended in proxy). Possible consequences:
1. You can't see the profile of this newly created user after registration (404 response)
2. You can use this to spoof another user - just use the name of another user during registration, append %0a in proxy (when registration request is sent) and you will be finally recognized as this user in Phabricator (the same name presented/displayed). This way you can try to spoof another user.





## Discussion & Remediation Timeline
