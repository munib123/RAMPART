# Vulnerability: Readiness Probes not set in Deployments
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-readiness-probe-not-set.yaml`)

## Description
Checks for missing readiness probes in Kubernetes Deployments, which can lead to traffic being sent to unready containers

## Secure Mitigation
Define readiness probes in all containers within your Kubernetes Deployments to ensure that traffic is only routed to containers that are fully prepared to handle it.

