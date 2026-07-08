# Vulnerability: Slow Query Log Disabled for MySQL Database Servers
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-mysql-slowquerylog-disabled.yaml`)

## Description
Ensure that the "slow_query_log" database flag is enabled for your Google Cloud MySQL database instances in order to simplify the task of finding inefficient or time-consuming SQL queries for your MySQL databases. By default, the "slow_query_log" database flag is not enabled for Google Cloud MySQL instances.

## Secure Mitigation
Enable the "slow_query_log" flag for MySQL database instances in Google Cloud to log and analyze slow SQL queries, improving database performance and query efficiency.

