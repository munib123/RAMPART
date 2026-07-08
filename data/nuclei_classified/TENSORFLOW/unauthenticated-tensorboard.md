# Vulnerability: Tensorflow Tensorboard - Unauthenticated Access
**Classification:** TENSORFLOW
**Source:** Nuclei Template (`unauthenticated-tensorboard.yaml`)

## Description
Tensorflow Tensorboard was able to be accessed with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/data/plugins_listing
```

