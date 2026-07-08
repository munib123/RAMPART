# Vulnerability: CloudFormation Stack Policy - Not In Use
**Classification:** CLOUD
**Source:** Nuclei Template (`stack-policy-not-inuse.yaml`)

## Description
Ensure your AWS CloudFormation stacks are using policies as a fail-safe mechanism in order to prevent accidental updates to stack resources.

## Secure Mitigation
Implement a CloudFormation Stack Policy to restrict updates to critical resources, defining explicit rules for which resources can be modified during stack updates.

