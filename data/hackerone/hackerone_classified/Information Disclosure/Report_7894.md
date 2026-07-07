# HackerOne Report: Full path disclosure
**Report ID:** 7894
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
I signed up for localize with haxorsistz@gmail.com, and localize sent me a verification link which was:
`http://www.localize.io/verify/e6be646b24pdd3w6d5c27ppa9a267ee7`
When I visited that link I found it was showing the following error:
`Fatal error: Call to a member function setEmail_lastVerificationAttempt() on a non-object in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/index.php on line 120 `
which includes the full path of the website.This should be mitigated.

## Discussion & Remediation Timeline
