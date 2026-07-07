# HackerOne Report: Upload profile photo from URL
**Report ID:** 713
**Vulnerability Class:** Server-Side Request Forgery (SSRF)

## Vulnerability Information & PoC
Using this vulnerability users can upload images from any image URL. 
Just change upload type using inspect element  (from "type=file" to "type=url") , paste URL in text field and hit enter or click on "Update Profile". Your profile photo will be changed to photo from URL.

P.S  Im sorry for my bad english.


## Discussion & Remediation Timeline
