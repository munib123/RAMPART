# HackerOne Report: Group Invite not properly authenticated
**Report ID:** 46379
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
There is no check whether the inviting user is allowed to invite a user into a group and through manipulation a user may sent themself and invite to any group.

Example:
Group A created by User 1 with Owner invitation only with ID x
User 2 sends malicious himself invite with ID x and receives invite to Group A


API Call that needs to be fixed:
https://www.wnmlive.com/api/groups/invites

## Discussion & Remediation Timeline
