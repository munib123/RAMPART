# HackerOne Report: Apache2 /icons/ folder accessible
**Report ID:** 7923
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
The Apache2 icons folder is accessible from http://www.localize.io/icons/. This is not by definition dangerous, but removing the directory can help obfuscate the server version you're running, which may prevent targeted attacks against your web server.

To remove the directory you should look for `Alias "icons" [...]` somewhere in the Apache2 config files and comment out the line.

## Discussion & Remediation Timeline
