# HackerOne Report: Self-XSS in posts by formatting text as code
**Report ID:** 89505
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi I have found an XSS in Slack. To reproduce the issue, just follow this:

1. Go to your Slack account (accountname.slack.com)

2. Below you will see a plus (+) sign, click that, there will be three options, click "Create Post"

3. You will be redirected to a page where you will create it.

4. Type the payload. I used: <svg onload=alert(domain)>. then Highlight it..  on the left side, there are symbols... click it and choose this symbol: ( <>) which is for code..

5. XSS Pop-up

Youtube video for clearer details:

https://youtu.be/dIvNeb2aRrU


THANKS!

## Discussion & Remediation Timeline
