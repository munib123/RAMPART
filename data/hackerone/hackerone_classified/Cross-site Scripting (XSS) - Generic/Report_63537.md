# HackerOne Report: XSS in https://app.mavenlink.com/workspaces/
**Report ID:** 63537
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
My name of mavelink account causes cross site scripting vulnerability

my name="><img src=x onerror=prompt(31);>

go to  https://app.mavenlink.com/workspaces/8591867/gantt

and click "save snapshot" button  than save it

When You save it you will get javascrip alert from "Can be viewed by ">" area beucae my mavelink name ("><img src=x onerror=prompt(31);>)


## Discussion & Remediation Timeline
