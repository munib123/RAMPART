# HackerOne Report: XSS on partners.uber.com
**Report ID:** 42393
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello,

I have discovered a reflected XSS on partners.uber.com 

When accessing https://partners.uber.com/signup/global/ with the appropriate parameters, for example: https://partners.uber.com/signup/global/?referrer_uuid=21f5fbbd-b79f-4a16-9976-01096fb556c7&place_id=ChIJPaCKh-tmA4wR7JEkNDrNDSU&utm_source=twitter&location=Carolina%2C+Carolina%2C+Puerto+Rico&lat=18.3807819&lng=-65.95738719999997 in a browser where the page has not been accessed previously in the current session (no session cookie on partners.uber.com), the GET-parameter ```location``` is reflected in the page without validation/sanitation.

POC (tested with Firefox 34.0):
https://partners.uber.com/signup/global/?place_id=ChIJPaCKh-tmA4wR7JEkNDrNDSU&location=Carolina<script>alert(1)</script>a%2C+Carolina"%2C+Puerto+Rico&lat=18.3807819&lng=-65.95738719999997

The best,
Simon


## Discussion & Remediation Timeline
