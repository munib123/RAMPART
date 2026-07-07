# HackerOne Report: XSS in the input
**Report ID:** 12389
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
https://app.respond.ly/create
once there go to Team Name and input the code ?'"--></style></script><script>alert(1337)</script> and put the email as a valid one and should inject the XSS code even should show when u login all the time.

Thanks,
Jordan Jones
@CEHSecurity 

## Discussion & Remediation Timeline
