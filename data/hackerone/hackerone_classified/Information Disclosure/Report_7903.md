# HackerOne Report: Path Disclosure (Info Disclosure) in  http://www.localize.io
**Report ID:** 7903
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hello,
I found a information disclosure vulnerability.
How to reproduce:
GET : http://www.localize.io/
POST : sign_in[username][]=test&sign_in[password][]=test

The info from page is
Warning: trim() expects parameter 1 to be string, array given in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/index.php on line 732
Is disclosed the path of the site.
Regards,
    Florin

## Discussion & Remediation Timeline
