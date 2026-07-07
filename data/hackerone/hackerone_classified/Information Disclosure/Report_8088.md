# HackerOne Report: Full Path Disclosure (FPD) in www.localize.io
**Report ID:** 8088
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,
I found an information disclosure vulnerability/Full Path Disclosure on your application.

Proof of Concept
-------------------------

GET  : http://www.localize.io/pages/create_project/ [project ID]
POST CONTENT: CSRFToken=TOKEN VALUE&create_project[visibility]=1&create_project[name][]=My+Android&create_project[defaultLanguage]=1&create_project[editRepositoryID][]=72

Just Add "[]" after *create_project[name]* and *create_project[editRepositoryID]*

### The information from page:
> Warning: trim() expects parameter 1 to be string, array given in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/classes/UI.php on line 1495

I Also Added a Screenshot of that FPD as attachment..
Hope You'll fix this one..
Thanks

## Discussion & Remediation Timeline
