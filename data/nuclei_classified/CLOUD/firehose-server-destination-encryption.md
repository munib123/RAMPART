# Vulnerability: Firehose Delivery Stream Destination Encryption - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`firehose-server-destination-encryption.yaml`)

## Description
Ensure that your Kinesis Firehose delivery stream data records are encrypted at destination (i.e. Amazon S3) in order to meet regulatory requirements and protect your Firehose data at rest.

## Secure Mitigation
Enable encryption for Firehose delivery stream destinations to ensure that all data is encrypted at rest, safeguarding sensitive information from unauthorized access and potential data breaches.

