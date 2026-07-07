# HackerOne Report: Stored XSS {dangerous?} https://www.khanacademy.org/coach/roster/?listId=allStudents
**Report ID:** 6369
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi,

when you go to https://www.khanacademy.org/coach/roster/?listId=allStudents and press on add class you have the possebility to add a class (obvious). when you name it "><img src=x onerror=alert(4)> it will stay persistent.

quite dangerous

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
