# HackerOne Report: Open Redirect login account
**Report ID:** 16718
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
An open redirect is an application that takes a parameter and redirects a user to the parameter value without any validation. This vulnerability is used in phishing attacks to get users to visit malicious sites without realizing it.

###Reproduction Instructions 

go to `www.[TEAM].slack.com/?redir=llink?url=https://twitter.com/` log in your account on this link then redirect to twitter,google and any webiste you want.


###Proof of concept:
```
https://asdasda.slack.com/?redir=llink?url=https://twitter.com/
```


Regards,
Jayson Zabate

## Discussion & Remediation Timeline
