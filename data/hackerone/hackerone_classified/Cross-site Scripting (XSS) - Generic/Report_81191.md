# HackerOne Report: [now.informatica.com] Reflective Xss
**Report ID:** 81191
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
http://now.informatica.com/en_data-integration-for-dummies_book_2642.html?source=Homepage
The issue is located here. I will be including a video demonstrating this vulnerability 
Xss vector used: <svg onload=confirm(document.domain)>xs 

## Discussion & Remediation Timeline
