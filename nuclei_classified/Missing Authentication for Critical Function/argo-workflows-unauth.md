# Nuclei Template: Argo Workflows - Unauthenticated Dashboard
**Template ID:** argo-workflows-unauth
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`argo-workflows-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Argo Workflows dashboard is accessible without authentication. Argo Workflows is a Kubernetes-native workflow engine that can execute arbitrary containers and commands. Unauthenticated access allows viewing, creating, and modifying workflows.

## Impact
An attacker can view all workflow executions and their logs (potentially containing secrets), submit new workflows that execute arbitrary containers in the Kubernetes cluster, and access service account tokens for further cluster exploitation.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/v1/workflows/argo
```

## Remediation
Configure Argo Workflows SSO authentication or set --auth-mode=server in the argo-server deployment. Apply Kubernetes RBAC policies to restrict workflow creation.

## References
- https://argo-workflows.readthedocs.io/en/latest/argo-server-auth-mode/
- https://argo-workflows.readthedocs.io/en/latest/argo-server-sso/
