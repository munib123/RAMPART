# HackerOne Report: Flash Player information disclosure (etc.) CVE-2015-3044, PSIRT-3298
**Report ID:** 63324
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
The vulnerability allows a malicious Flash app on a website to read and write Local Shared Objects belonging to any website. As a special case, LSO's of macromedia.com contain global Flash settings. Overwriting them allows e.g. unlimited access to camera and microphone of the target user. Other attacks are possible too, e.g. disclosure of sensitive information in LSO's (website-dependent) and triggering the double free bug in Flash Player Settings Manager reported separately.

The bug can be exploited with malformed jar: URLs on Firefox. Other browsers require other ways of spoofing the host, e.g. HTTP MITM or DNS spoofing.

The bug was patched in April 2015 and additional hardening in May 2015.

## Discussion & Remediation Timeline
