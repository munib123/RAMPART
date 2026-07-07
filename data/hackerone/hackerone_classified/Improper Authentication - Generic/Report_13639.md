# HackerOne Report: X/Csrf token problem
**Report ID:** 13639
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
I found that you are using X/Csrf token as a protection against CSRF attacks.

But you are using same X/Csrf token in and out.

eg
z3qrwilV8lz7CXsMhmvqxn+93GDZm/m9w/d5DZjoj8w=

This token is same before and after log-in.
This must be patch as it me result session hacks. 

## Discussion & Remediation Timeline
