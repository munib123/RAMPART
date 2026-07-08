# Vulnerability: CloudFormation Termination Protection - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`stack-termination-disabled.yaml`)

## Description
Ensure that Termination Protection safety feature is enabled for your Amazon CloudFormation stacks in order to protect them from being accidentally deleted.

## Secure Mitigation
Enable termination protection for critical CloudFormation stacks by setting TerminationProtection to true in the stack settings, preventing accidental deletions.

