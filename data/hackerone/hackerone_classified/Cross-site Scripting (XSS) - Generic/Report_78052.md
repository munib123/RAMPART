# HackerOne Report: xss in group
**Report ID:** 78052
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
step:

payload : "><svg onload=prompt(document.domain) >

1.first create a new group.
2. now create new post,
3. now put payload in new topic and than click on add poll.
4. xss executed.


## Discussion & Remediation Timeline
