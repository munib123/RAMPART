# HackerOne Report: Stored XSS in concrete5 5.7.0.4.
**Report ID:** 30019
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello.

I found stored XSS in concrete5 5.7.0.4.

If the user have file upload permission
the user can upload the file named like 
"><svg onload=confirm(document.cookie)>.txt
and the file name is displayed without being escaped.

and when other user access the file manager page,
Execute Javascript code on page load.

Regards.


## Discussion & Remediation Timeline
