# Vulnerability: Kubernetes Exposing Host's Docker Socket
**Classification:** CLOUD
**Source:** Nuclei Template (`kubernetes-exposing-docker-socket-hostpath.yaml`)

## Description
Exposing host's Docker socket to containers via a volume.

## Secure Mitigation
Remove 'docker.sock' from hostpath to prevent this.

