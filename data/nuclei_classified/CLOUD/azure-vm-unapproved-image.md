# Vulnerability: Azure VM Not Using Approved Image
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-unapproved-image.yaml`)

## Description
Ensure that all the Azure virtual machine (VM) instances necessary for your application stack are launched from an approved base Azure machine image, known as golden machine image, in order to enforce application security best practices, consistency, and save time when scaling your application.

## Secure Mitigation
Ensure all Azure VM instances are launched from approved machine images. Update any instances that are not using the approved images.

