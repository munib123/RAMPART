# HackerOne Report: stored XSS in concrete5 5.7.2.1
**Report ID:** 38890
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello.

I found stored XSS in concrete5 5.7.2.1.

If the user have file upload permission
the user can upload the file named like 
"><img src=0 onerror=confirm(document.cookie)>.txt
or 
change title like below
<svg onload=confirm(document.cookie)>
on the properties page.

and when other user access the file manager page,
and open the delete page or open the properties page,
Javascript execute.

I reported same issue in 5.7.0.4. and fixed [#30019]
but this fix is not sufficient.

Regards.


## Discussion & Remediation Timeline
