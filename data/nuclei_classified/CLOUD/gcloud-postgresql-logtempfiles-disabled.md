# Vulnerability: Log Temporary Files Flag Disabled in PostgreSQL Database Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-postgresql-logtempfiles-disabled.yaml`)

## Description
Ensure that the "log_temp_files" database flag is set to 0 (enabled) for all your Google Cloud PostgreSQL database instances. PostgreSQL database engine can create temporary files for actions such as sorting, hashing, and temporary query results when these operations exceed the amount of memory specified for the "work_mem" setting. Setting "log_temp_files" flag to 0 causes all temporary file information to be logged, while positive configuration values log only files whose size is greater than or equal to the specified number of kilobytes.

## Secure Mitigation
Set the "log_temp_files" database flag to 0 for your PostgreSQL database instances to ensure temporary file operations are logged.

