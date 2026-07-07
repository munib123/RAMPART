# HackerOne Report: [careers.informatica.com] Cross Site Script Vulnerability on informatica
**Report ID:** 42537
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Information:- Vulnerability resides on the Carriers page of informatica, where search bar of the carrier page failed to sanitized the users query and hence gives the XSS popup. 

Vulnerable URL:- https://careers.informatica.com/

Payload:- "><svg/onload=prompt(1);>

Steps to Reproduce the Vulnerability
1. Open Carriers page of Informatica and search for anything. 
2. On the next page (search Result page) of search result, there is a option of All Location. 
3. Now search on the All Location field with you JavaScript Payload. (For E.g :- "><svg/onload=prompt(1);>)
4. As it search, you will get the XSS popup on your Screen which shows that page is vulnerable to XSS vulnerability.

Hope you got the issue and fixed it soon.

## Discussion & Remediation Timeline
