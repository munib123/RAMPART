# HackerOne Report: URL redirection flaw
**Report ID:** 2622
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
An open redirect is an application that takes a parameter and redirects a user to the parameter value without any validation. This vulnerability is used in phishing attacks to get users to visit malicious sites without realizing it.

Steps to reproduce:

1) Go to this URL:

https://slack.com/checkcookie?redir=http://www.likelo.com

Proper checks should be there on the redir parameter that should only allow to redirect on slack.com URL.

Please have a look.

Best regards,
Anand

## Discussion & Remediation Timeline
