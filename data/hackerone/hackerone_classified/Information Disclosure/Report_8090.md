# HackerOne Report: Full Path Disclosure / Info Disclosure in Creating New Group
**Report ID:** 8090
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,
I found another information disclosure vulnerability/Full Path Disclosure on your application.
this time its on Creating New Group Section.

Proof of Concept
-------------------------

GET  : http://www.localize.io/pages/create_project/ [project ID]
POST CONTENT: CSRFToken=TOKEN VALUE&addGroup[name][]=new+group

I just Added "[]" after *addGroup[name]* and Replied.

### The information from page:
> Warning: trim() expects parameter 1 to be string, array given in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/classes/Phrase.php on line 213

I Also Added a Screenshot of that FPD as attachment..
Hope You'll fix this one also..
Thanks

## Discussion & Remediation Timeline
