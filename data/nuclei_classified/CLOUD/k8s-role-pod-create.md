# Vulnerability: Roles that have pod create permissions
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-role-pod-create.yaml`)

## Description
Checks for roles that have permissions to create pods.

## Secure Mitigation
Configure pods so they are not assigned the permission to create other pods

