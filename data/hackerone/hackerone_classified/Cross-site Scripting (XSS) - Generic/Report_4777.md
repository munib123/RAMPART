# HackerOne Report: XSS in Theme Preview Tools File
**Report ID:** 4777
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
https://github.com/concrete5/concrete5/blob/master/web/concrete/tools/themes/preview.php#L7

Note that one of those values near the end is not escaped.

## Discussion & Remediation Timeline
