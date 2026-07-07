# HackerOne Report: XSS - Gallery Search Listing
**Report ID:** 76713
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
HI.
If you upload video having title with XSS payload. and search for the video, the dropdown listing will execute the payload.

https://www.zaption.com/gallery/search?q=%3E%3Cimg

I need not to upload the payload, I utilized already uploaded videos.


You can also execute the payload by just start typing into the search box with
"><img

That's it, XSS will be executed.

## Discussion & Remediation Timeline
