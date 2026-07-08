# Vulnerability: Kubernetes Ingress-Nginx Valid AdmissionReview - Detection
**Classification:** TECH
**Source:** Nuclei Template (`ingress-nginx-valid-admission.yaml`)

## Description
Sends a valid minimal AdmissionReview JSON to reliably detect Kubernetes Ingress-Nginx Admission webhook endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /validate HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": {
    "uid": "{{string}}",
    "kind": {
      "group": "networking.k8s.io",
      "version": "v1",
      "kind": "Ingress"
    },
    "operation": "CREATE",
    "object": {
      "metadata": {
        "name": "test-{{string}}",
        "namespace": "default"
      },
      "spec": {
        "rules": [
          {
            "host": "example.com",
            "http": {
              "paths": []
            }
          }
        ]
      }
    }
  }
}
```

