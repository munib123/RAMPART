# Nuclei Template: Mozilla Pollbot - Open Redirect
**Template ID:** pollbot-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`pollbot-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Mozilla Pollbot contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/%0A/interact.sh/
```

## References
- https://bugzilla.mozilla.org/show_bug.cgi?id=1753838
- https://github.com/mozilla/PollBot
