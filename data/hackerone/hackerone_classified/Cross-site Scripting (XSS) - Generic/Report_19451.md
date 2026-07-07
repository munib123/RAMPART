# HackerOne Report: IFXSS (image filename XSS) by creating a new Photo Gallery
**Report ID:** 19451
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello team! I think I've found a Stored XSS in the Photo Gallery. To reprodruce the possible vulnerability we must:
1. Login into our account.
2. Go to https://staging.uzbey.com/user/other-albums and click on the "add new album" button.
3.  Add random values and any image with this name ---> "onerror="alert(1)"a=".jpg
4. Publish your gallery.
5. XSS! 
Also, if you click on the image error icon you will obtain the alert.
I will attach a few images as a little help for understand my Proof of Concept of the vulnerability.
 Kind regards.

## Discussion & Remediation Timeline
