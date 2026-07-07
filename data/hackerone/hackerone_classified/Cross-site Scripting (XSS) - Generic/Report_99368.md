# HackerOne Report: an xss issue
**Report ID:** 99368
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
i found an xss issue here :
https://www.algolia.com/explorer#?index=test&tab=ranking
i tried to put  an xss payload ("><img src=x onerror=alert(0)>)
in index > ranking> so i put the xss payload in Ranking formula then hit save ...when it is being saved the xss payload is being stored that upon Indices xss payload executed
p.s please screen shot


## Discussion & Remediation Timeline
