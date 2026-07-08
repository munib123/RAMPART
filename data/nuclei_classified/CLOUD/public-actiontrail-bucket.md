# Vulnerability: ActionTrail Log Buckets - Publicly Exposed
**Classification:** CLOUD
**Source:** Nuclei Template (`public-actiontrail-bucket.yaml`)

## Description
Identify any publicly accessible ActionTrail trail log buckets in order to determine if your Alibaba Cloud account could be at risk. A publicly accessible trail bucket is a bucket were all users, including anonymous users, can perform read and write operations on the objects within the bucket.

