# HackerOne Report: Cross site scripting on ads.twitter.com
**Report ID:** 28150
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

Steps to reproduce the issue:
1) Go to this link https://ads.twitter.com/accounts/XXXX/tweets where is XXXX is your account id.

2) Click on Compose Tweet option and enter "><svg/onload=prompt(123);>

3) Click on "Tweet" Button now.

You will prompt dialog box with "123" in it.

POC video: https://www.dropbox.com/s/64li7wv7gq2brlz/twitterxss.mov?dl=0

Please fix this.

Best Regards,
Anand Prakash

## Discussion & Remediation Timeline
