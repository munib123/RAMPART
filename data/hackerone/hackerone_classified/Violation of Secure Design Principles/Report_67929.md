# HackerOne Report: Redirection Page throwing error instead of redirecting to site
**Report ID:** 67929
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Hello 

I was just testing and found that http://anysite.com.com/index.php?ref=&quot;&gt;&lt;svg/onload=window.onerror=alert;throw/XSS/;// does not shows the usual External link warning page, but shows some error page .

Thanks

## Discussion & Remediation Timeline
