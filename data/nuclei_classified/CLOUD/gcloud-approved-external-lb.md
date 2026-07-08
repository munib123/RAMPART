# Vulnerability: Unapproved External Load Balancers in Google Cloud Projects
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-approved-external-lb.yaml`)

## Description
Ensure that your web applications are using only approved external load balancers to comply with your organization's security and industry requirements. Using unapproved load balancers could expose your applications to vulnerabilities. The approved load balancers must be defined in the conformity rule settings, in the Trend Cloud One™ – Conformity account console.

## Secure Mitigation
Ensure all used external load balancers are approved in the Trend Cloud One™ – Conformity account console. Replace unapproved load balancers with approved ones.

