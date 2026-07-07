# HackerOne Report: Sensitive file
**Report ID:** 7968
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
A possible sensitive file has been found. This file is not directly linked from the website. This check looks for common sensitive resources like password files, configuration files, log files, include files, statistics data, database dumps. Each one of these files could help an attacker to learn more about his target.
This vulnerability affects /.gitignore.
HTML
.idea/* temp/*/* uploads/*.xml img/contact.php config.php 

## Discussion & Remediation Timeline
