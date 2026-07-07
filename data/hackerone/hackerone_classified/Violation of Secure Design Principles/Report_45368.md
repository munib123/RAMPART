# HackerOne Report: ftp upload of video allows naming that is not sanitized as the manual naming
**Report ID:** 45368
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
I have uploaded via ftp (Vimeo Pro account) a filename

""><img src = x onerror=alert(2)>".mp4

And as you can see in the screenshot it is put automatically as the name of the video. But I cannot put this name (""><img src = x onerror=alert(2)>".mp4) manually

So I think it needs the same sanitization of the name as it's done after the manual editing.

Even if the XSS is not reflected now (in this case) it can be when doing other actions involving the video name (sharing, follow, link, like etc)

## Discussion & Remediation Timeline
