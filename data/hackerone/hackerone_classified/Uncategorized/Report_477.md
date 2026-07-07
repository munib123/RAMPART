# HackerOne Report: Flawed account creation process allows registration of usernames corresponding to existing file names
**Report ID:** 477
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
As requested by Alex:
"You mentioned in the report to contact you on this account instead. Is this the email address you prefer to use for payment? If so, would you mind resubmitting the issue from this account so we can issue a payout to the proper account?"

----------

The account creation process allows to set up account names corresponding to names of server ressources, e.g. I just successfully created an account robots.txt which results in a profile path of https://hackerone.com/robots.txt and results in an bugged account as accessing account settings etc is impossible.

I'd recommend moving away from filtering names and from profiles being available directly under .com/ and changing it to something more reliable like .com/users/profilename

The robots.txt account can be deleted. I only created it for testing purpose.

Cheers,
Florian

## Discussion & Remediation Timeline
