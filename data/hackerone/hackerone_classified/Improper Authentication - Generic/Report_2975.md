# HackerOne Report: Deleting Teams implemenation
**Report ID:** 2975
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
When deleting a team, it needed a proper authentication. It does not re authenticate the user if he is the legit owner who is trying to delete the team.

In a case where, we leave our account for a few minutes and somebody walks by then quickly delete our team.

Clifford

## Discussion & Remediation Timeline
