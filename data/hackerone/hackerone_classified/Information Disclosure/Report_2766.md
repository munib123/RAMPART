# HackerOne Report: Email enumeration
**Report ID:** 2766
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Navigate to the page - https://slack.com/signin
Now, entering invalid email address returns an erroneous response.
However, if you enter a valid email address like admin@slack.com, it redirects you to a different page where it asks you to choose teams that belongs to admin@slack.com.
You can then click on any option which will in turn redirect to that particular team's page on the slack domain like <teamname>.slack.com.

The above vulnerability can be used to enumerate email address of the users of the application as well as learn more about teams associated with that email address. 


## Discussion & Remediation Timeline
