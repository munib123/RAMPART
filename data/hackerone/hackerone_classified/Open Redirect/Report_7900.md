# HackerOne Report: OAuth open redirect
**Report ID:** 7900
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
An attacker can use an open redirect vulnerability in the Twitter OAuth process to redirect someone to his/her webpage, while also obtaining the OAuth token and verifier of the victim. 

The vulnerability is right here: https://app.respond.ly/_oauth/twitter/?requestTokenAndRedirect=https://hackerone.com. When someone authorizes their Twitter account using that URL, the redirect will go to https://hackerone.com.

Recommendation: make sure the `requestTokenAndRedirect` paramater only accepts hosts on whitelisted domains.

## Discussion & Remediation Timeline
