# Vulnerability: Configure Dead Lettering for Pub/Sub-Triggered Functions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-func-pubsub-dlt-missing.yaml`)

## Description
Ensure that Google Cloud functions triggered by Pub/Sub have a Dead-Letter Topic (DLT) configured to handle undeliverable messages. To achieve this, configure your Pub/Sub subscriptions with a maximum number of delivery attempts. If a message cannot be delivered, it will be sent to the designated Dead-Letter Topic (DLT).

## Secure Mitigation
Configure a Dead-Letter Topic for each Pub/Sub-triggered function by setting up the necessary Pub/Sub subscription settings.

