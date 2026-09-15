# Nuclei Template: ElasticBeanstalk Subdomain Takeover Detection
**Template ID:** elasticbeanstalk-takeover
**Vulnerability Class:** Improper Resource Shutdown or Release
**Severity:** High
**CWE:** CWE-404
**Source:** Nuclei Template (`elasticbeanstalk-takeover.yaml`)

## Vulnerability Information & PoC

## Description
ElasticBeanstalk subdomain takeover detected. A subdomain takeover occurs when an attacker gains control over a subdomain of a target domain. Typically, this happens when the subdomain has a canonical name (CNAME) in the Domain Name System (DNS), but no host is providing content for it.

## References
- https://github.com/EdOverflow/can-i-take-over-xyz/issues/147
- https://twitter.com/payloadartist/status/1362035009863880711
- https://www.youtube.com/watch?v=srKIqhj_ki8
