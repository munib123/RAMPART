# HackerOne Report: CSS leaks SCSS debug info
**Report ID:** 2221
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Download CSS style sheet referenced from the HTML and do:

grep -oP "file.:.*?scss" application-facbdb64a504bb08ec272860320e1941.css | sort | uniq

As you can see it exposes information about the file system, source CSS files and software used.

See enclosed file for a dump of the output of the command above.

## Discussion & Remediation Timeline
