# HackerOne Report: Post in private groups after getting removed
**Report ID:** 51817
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
Steps to reproduce:

1. A user(victim) have a private video and he have added it on his private groups. Now the group members can see it and comment to it.
2. The attacker is on the group and he adds a new comment and capture the request using burp proxy.
3. Then the attacker is removed from the group by the victim.
4.Now the attacker can't access the video and group anymore. But he can comment on that video by replaying the request captured in step 2.

## Discussion & Remediation Timeline
