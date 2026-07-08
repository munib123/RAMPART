# Vulnerability: Dead Letter Topic Not Enabled for Google Pub/Sub Subscriptions
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-pubsub-deadletter-disabled.yaml`)

## Description
Ensure that each Google Cloud Pub/Sub subscription is configured to use a dead-letter topic (DLQ) to capture undeliverable messages. Pub/Sub subscriptions allow for a maximum number of delivery attempts. Messages that cannot be delivered after the maximum attempts are sent to the dead-letter topic, ensuring they can be reviewed and handled appropriately.

## Secure Mitigation
Configure a dead-letter topic for all Google Cloud Pub/Sub subscriptions to capture undeliverable messages. This ensures messages can be retained and addressed later.

