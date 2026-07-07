# HackerOne Report: Accessing title of the report of which you are marked as duplicate
**Report ID:** 75556
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Hello,

You can see the title of the report of which you are marked as Duplicate

Steps to Reproduce:
1. Report a bug to a team
2. Now that team marks your bug as 'Duplicate (#Report_ID).(but does not shares the report with you)
3. When that bug is marked as Resolved then you can see the title of that bug at https://hackerone.com/settings/reputation/log

This is clearly a lack of authentication as unless the bug is not shared or it is not public you should not be allowed to see any of its content.

Thanks

## Discussion & Remediation Timeline
