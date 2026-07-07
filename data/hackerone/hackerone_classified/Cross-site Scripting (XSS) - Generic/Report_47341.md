# HackerOne Report: Reflected xss in user name thru cookie
**Report ID:** 47341
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Imagine, that we have user A with name - name<script>alert(1)</script>
And user B
User B request a sim card and the Add authorization to user A (of course this is not the common way to exploit).
As a result we have xss thru user name in flash message thru cookie.
And (!) we got properly singed cookie with xss payload
messages="29972147bc558baf382bbeb0b829d4efec82de2f$[[\"__json_message\"\0540\05425\054\"Authorization will be given to name<script>alert(1)</script> once this user confirms.\"]]"; Path=/


## Discussion & Remediation Timeline
