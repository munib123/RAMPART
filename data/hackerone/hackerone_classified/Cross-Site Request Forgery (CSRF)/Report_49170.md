# HackerOne Report: Information disclosure - emails disclosed in response > staging.seatme.us
**Report ID:** 49170
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hello,
I found a  info disclosure vulnerability. We can enumerate emails via user_id parameter from Manage users.

And I found that :

>ID 1 is ██████
ID 514755 is ████████
ID 514775 is █████
ID 514764 is ███████

I attached photos from burp repeater to be more explicit.

We can easily bruteforce user_id parameter with ids to harvest user's emails.


Regards,
  Florin

## Discussion & Remediation Timeline
