# Vulnerability: ElasticBeanstalk Subdomain Takeover Detection
**Classification:** CWE-404
**Source:** Nuclei Template (`elasticbeanstalk-takeover.yaml`)

## Description
ElasticBeanstalk subdomain takeover detected. A subdomain takeover occurs when an attacker gains control over a subdomain of a target domain. Typically, this happens when the subdomain has a canonical name (CNAME) in the Domain Name System (DNS), but no host is providing content for it.

