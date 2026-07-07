# HackerOne Report: Full Path Disclosure on [smarthistory.khanacademy.org]
**Report ID:** 6362
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hello, I have found a full path disclosure on a website that runs a wordpress installation. There isn't much to explain about this bug, as it's pretty self explanatory. What an attack can do with this bug is identify the full path, and the user the site is running under. If the attacker finds a vulnerability where he needs the full path, he can grab it from there.

Here's the proof of concept - http://smarthistory.khanacademy.org/blog/wp-content/plugins/podpress/getid3/write.php

To mitigate this vulnerability, either fix the syntax error, or remove the file if it is not necessary anymore after evaluation. 

Thank you.

## Discussion & Remediation Timeline
