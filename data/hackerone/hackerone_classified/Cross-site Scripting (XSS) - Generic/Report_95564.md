# HackerOne Report: Persistent XSS in image title
**Report ID:** 95564
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
When adding a title to uploaded images, one can insert XSS into the title which is then executed for anyone viewing the image.

PoC (contains a harmless XSS):
http://imgur.com/bSZwUBG&rAmpN4O

How to recreate:
1. Open the Image Options page for an album.
2. Press "Add Title / Description"
3. Enter some HTML into the title field. In my PoC, I used the following: <marquee><font size=72>XSS
4. Save. You are now redirected to the Image Options page, where the XSS is evaluated by the browser.

This XSS is persistent and will execute for anyone who visits the URL, in this case http://imgur.com/bSZwUBG&rAmpN4O

Images from steps 2, 3 and 4 attached.

## Discussion & Remediation Timeline
