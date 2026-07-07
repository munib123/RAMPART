# HackerOne Report: Reflected XSS in chat.
**Report ID:** 81757
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
hello 
login in the chat  and upload file with Payload name (code injection)
like  <img src="c" onerror=alert(1)>   the code html will execute 

<span>You are not allowed to upload '<img src="c" onload="alert(1)">' files, allowed types: jpg, jpeg, gif, png</span>



Hadji Samir

## Discussion & Remediation Timeline
