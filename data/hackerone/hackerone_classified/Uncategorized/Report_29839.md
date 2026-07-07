# HackerOne Report: GNU Bourne-Again Shell (Bash) 'Shellshock' Vulnerability
**Report ID:** 29839
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
GNU Bash versions 1.14 through 4.3 contain a flaw that processes commands placed after function definitions in the added environment variable, allowing remote attackers to execute arbitrary code via a crafted environment which enables network-based exploitation.  

Original disclosure: http://www.openwall.com/lists/oss-security/2014/09/24/11

Detailed analysis by lcamtuf:
- http://lcamtuf.blogspot.com/2014/09/quick-notes-about-bash-bug-its-impact.html
- http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html


## Discussion & Remediation Timeline
