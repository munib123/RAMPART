# HackerOne Report: Team member invitations to sandboxed teams are not invalidated consistently
**Report ID:** 46429
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
hello today i found a Bug about Auth in Send invitation to member to join the team ,, so if Now 
The Victim Send invition to Another Victim Account to join the team as a Manager,, the link of the invitation is will Be Valid For Many Many Many time to Accept the invtiation from Another Accounts in H1 so let's say example :
A send invtation emai to B

the other Acconts could access to the Account and open it and Accept the invtiation Without invtiet them !!!

the invetion url :https://hackerone.com/invitations/54a725ee8c5b8d7c1225e8b486716145

the poc :
http://youtu.be/dL7FOBCssFE

## Discussion & Remediation Timeline
