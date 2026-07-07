# HackerOne Report: flash content type sniff vulnerability in api.slack.com
**Report ID:** 3455
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hi,

I have found a flash content type sniff vulnerability could allow attackers get user's team auth2 tokens. As the page lists user's teams and its security tokens, this could allow attackers to do csrf attacks.

Steps to reproduce:
1. Log in api.slack.com
2. after go to http://netfuzzer.com/api-slack-vuln2.html
3. wait 5 seconds until the page finish load
4. see your team's security tokens.

Cheers,
Mario



## Discussion & Remediation Timeline
