# HackerOne Report: Unexpected array leaks information about the system
**Report ID:** 7888
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
By changing a string parameter on the `/pages/settings` page to an array (see example.png) and submitting the form, the page shows an error message leaking information about the server and functions used (see error.png). This works on multiple POST parameters.

    Warning: trim() expects parameter 1 to be string, array given in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/index.php on line 85

## Discussion & Remediation Timeline
