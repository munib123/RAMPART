# HackerOne Report: No Limitation on Following allows user to follow people automatically!
**Report ID:** 43846
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hello,
i'm not sure it's intentional or somehow you missed it, I noticed that when User follow people on Vimeo, CSRF token of the request doesn't change at all.
It's become something like a static code for a single session.
ex:
POST: https://vimeo.com/user12345 <= [ID]
POST CONTENT: action=toggle_follow&token=[TOKEN]

An attacker can misuse this function with intruder/repeater and Follow as much people he want to follow.
like all he have do is put the URL on repeater/intruder with auto increment value (a number increased by 1 for every request). that's it.

for testing purpose, i ran a intruder attack with 500 user id and it successfully followed all available users from the list. (screenshot attached)
you can check here too: https://vimeo.com/faisalahmed/following

FIX:
it can be fixed by implementing unique CSRF token for every request (regenerating CSRF token)
or you can limit following feature.

Looking forward!

## Discussion & Remediation Timeline
