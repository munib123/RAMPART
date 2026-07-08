# Vulnerability: Export All Log Entries Using Sinks Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-logging-sink-not-configured.yaml`)

## Description
Ensure there is at least one sink used to export copies of all the log entries available within your Google Cloud Platform (GCP) project. A sink is an object created to hold a log query and a destination. You can export logs by creating one or more log sinks that include a log query and an export destination. As Google Cloud Logging service receives new log entries, they are compared against each sink. If a log entry matches a sink object query, then a copy of the log entry is written to the sink's export destination.

## Secure Mitigation
Create a log sink with a blank filter to export all log entries within the project. Ensure the export destination aligns with your organizational logging strategy.

