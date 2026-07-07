# HackerOne Report: Simplenote Silverlight cross-domain policy misconfiguration
**Report ID:** 7571
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
The Simplenote application publishes a [Silverlight cross-domain policy](https://app.simplenote.com/clientaccesspolicy.xml) which allows access from any domain.  

    <allow-from http-request-headers="*">
      <domain uri="http://*"/>
      <domain uri="https://*"/>
    </allow-from>

Allowing access from all domains means that any domain can perform two-way interaction with this application. This policy is likely to present a significant security risk.

If a user is logged in to the application, and visits a domain allowed by the policy (any domain, in this case), then any malicious content running on that domain can potentially gain full access to the application within the security context of the logged in user. 

## Discussion & Remediation Timeline
