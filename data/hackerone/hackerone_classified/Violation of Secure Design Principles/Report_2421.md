# HackerOne Report: Value of JSESSIONID  and XSRF token parameter in cookie remains same before and after login
**Report ID:** 2421
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Here are two same values captured via intercepting the request and the value of JSESSIONID and XSRF remains same before and after login
JSESSIONID=m8u0pm8mjvckm1ya8da4oqlfb0pd34iw38lr; 
XSRF-TOKEN=6B025F41D13BC02E9D658409BAC23F84;

This could lead to further threats such as session hijacking etc



## Discussion & Remediation Timeline
