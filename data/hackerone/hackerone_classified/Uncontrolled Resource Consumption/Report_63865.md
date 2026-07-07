# HackerOne Report: Potential denial of service in hackerone.com/<program>/reward_settings
**Report ID:** 63865
**Vulnerability Class:** Uncontrolled Resource Consumption

## Vulnerability Information & PoC
While setting the bounty for the program, if I set the bounty to a large value (over 1,000,000 digits) and send the request the website hangs for about a minute and a half, then pops up an error page saying there is an error on Hackerone's Host end.

Time taken to repsond : 76856 Millisecond = 76.856 Seconds
Error Code: `Error 522`
URL: https://hackerone.com/<program>/reward_settings

The Request and response is attached in this Report.

Vulneurabe paramater `base_bounty`

Request parameters format:

    {"handle":"<program>","errors":{},"offers_bounties":true,"advertise_bounties":true,"base_bounty":"1111....till 1,000,000 digits","hide_bounty_amounts":false,"team_state":"sandboxed","allowed_to_disable_bounties?":true}

## Discussion & Remediation Timeline
