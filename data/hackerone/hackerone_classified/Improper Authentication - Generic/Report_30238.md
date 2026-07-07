# HackerOne Report: New Device confirmation tokens are not properly validated.
**Report ID:** 30238
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hi, team
I noticed that the new device confirmation code sent by your server is not validated .
POC:
1) Login to a new computer and ask for confirmation code two times.
Say around at 12.00 PM and at 12.01 PM
2) Now verify the device with the confirmation token which arrived at 12.01 PM
and after doing your work
go to https://www.coinbase.com/settings/security_settings
and remove that device .
say around 12.30 PM
3) Now you need to confirm the device once again and your server will send the new device confirmation code to user's email address at 12.30 PM
4) Here this time  use the confirmation code which arrived at 12.00 PM and u can see that , your device is confirmed.

Fix:
Invalidate all the previous confirmation tokens as soon as new token is generated.

## Discussion & Remediation Timeline
