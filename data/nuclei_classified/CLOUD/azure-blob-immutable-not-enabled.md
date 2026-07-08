# Vulnerability: Azure Blob Immutable Storage Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-blob-immutable-not-enabled.yaml`)

## Description
Ensure that Immutable Blob Storage feature is enabled for Microsoft Azure Storage blob containers that hold sensitive and business-critical information. Immutable Blob Storage enables you to store critical, production data objects in a WORM (Write Once, Read Many) state. This state makes the data non-erasable and non-modifiable for a user-specified time interval. Azure blob objects can be created and read, but not modified or deleted, for the duration of the retention interval configured. The feature supports two types of policies that you can apply to a container for retaining the data within the specified container in a non-modifiable and delete-protected state.

## Secure Mitigation
Apply an appropriate time-based immutability policy or a legal hold policy to your Azure Storage blob containers to protect sensitive and business-critical data from being modified or deleted.

