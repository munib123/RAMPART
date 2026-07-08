# Vulnerability: Argo Workflows - Unauthenticated Dashboard
**Classification:** CWE-306
**Source:** Nuclei Template (`argo-workflows-unauth.yaml`)

## Description
Argo Workflows dashboard is accessible without authentication. Argo Workflows is a Kubernetes-native workflow engine that can execute arbitrary containers and commands. Unauthenticated access allows viewing, creating, and modifying workflows.

## Secure Mitigation
Configure Argo Workflows SSO authentication or set --auth-mode=server in the argo-server deployment. Apply Kubernetes RBAC policies to restrict workflow creation.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/workflows/argo
```

