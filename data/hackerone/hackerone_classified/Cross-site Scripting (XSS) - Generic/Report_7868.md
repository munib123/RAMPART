# HackerOne Report: XSS in Groups
**Report ID:** 7868
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Visit the following link after logging in:
http://www.localize.io/pages/create_project/3D

Add a new group with an XSS string (as group name) and you will see the XSS execting.


String used:
<object data=data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoNCk+></object>?

Thanks,
Ben

## Discussion & Remediation Timeline
