# HackerOne Report: xss in /browse/contacts/
**Report ID:** 38189
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
hey guys 

i just found an xss in openfolio

i just created an contact in google with  name as "><img src=x onerror=prompt(1)>  and gave an email as random 

url >> https://www.google.com/contacts/u/0/#contact/new


then i synced  openfolio with  google contacts 

then i went here >> https://openfolio.com/browse/contacts/

then i clicked on invite of  "><img src=x onerror=prompt(1)>  , i got the xss popup ~

POC >> http://postimg.org/image/6po3vo89l/




## Discussion & Remediation Timeline
