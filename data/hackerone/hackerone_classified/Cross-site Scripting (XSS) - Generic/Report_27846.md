# HackerOne Report: Stored xss
**Report ID:** 27846
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi!

There's a stored xss on ads.twitter.com under "Add New App" section at https://ads.twitter.com/accounts/18ce53wsl3g/campaigns/new_objective/app_installs. 

There's a option to add android application by Google play app id, so i searched for a app on play store with name " "><img src=x onerror=alert(1)>" " and then i got this app https://play.google.com/store/apps/details?id=com.rssappmaker.athe319.

So to reproduce this copy paste the app id "com.rssappmaker.athe319" in that box and then click on "add app" button. After that this xss will be triggered. See the attached image poc.png

Tested in latest version of chrome.

Thanks

## Discussion & Remediation Timeline
