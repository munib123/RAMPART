# HackerOne Report: Send AJAX request to external domain
**Report ID:** 97191
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello!

I would like to report about ability to send AJAX request from `hackerone.com` to external domain.

Here is PoC for the last version of Internet Explorer: https://hackerone.com/bugs?subject=%2Fbigbob.lv%2F1337.php%3Fdata%3D

If You visit it, You can see `Hello! This is custom text from external domain` text which is from JSON here https://bigbob.lv/1337.php

You can check console and see there 3 AJAX requests sent from `hackerone.com` to `bigbob.lv`.

It is possible because there is no filtration of `/` slash in JavaScript when it handles `subject` GET param. So, it allows to send AJAX requests to external domain because of `//`.

This PoC will work in old versions of popular browsers which don't support CSP (http://caniuse.com/#feat=contentsecuritypolicy).

I will try to achieve XSS.

Thanks!

## Discussion & Remediation Timeline
