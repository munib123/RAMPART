# HackerOne Report: Missing "size check" on files to upload could make memory leaks.
**Report ID:** 19532
**Vulnerability Class:** Memory Corruption - Generic

## Vulnerability Information & PoC
I noticed that there isn't any "size check" when someone tries to upload a flie through the "upload picture" option, this could generate a memory leak or also a kind of DoS and is deangerous with bigger and bigger files. So i first tried to upload a file of about 2,52 GB (see the pic) and no warning messaege about the size wasn't displayed (such as a 413 error message), and the site was unable to charge the page, it generated an huge solwdown of the connection to https://staging.uzbey.com. 

------Risks------

Someone interested could exploit that to make a designed wepay dosser software to take the website down and that colud also make a dangerous memory leak or exploitable overflows .

## Discussion & Remediation Timeline
