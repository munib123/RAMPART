# Vulnerability: Graylog REST API Endpoints - Exposure
**Classification:** TECH
**Source:** Nuclei Template (`graylog-api-exposure.yaml`)

## Description
Graylog is a centralized log management solution. According to the official documentation, it exposes multiple endpoints (some by default).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/api-docs
GET {{BaseURL}}/api/api-browser
GET {{BaseURL}}/api/cluster
GET {{BaseURL}}/api/dashboards
GET {{BaseURL}}/api/events/definitions
GET {{BaseURL}}/api/events/definitions/validate
GET {{BaseURL}}/api/events/notifications/test
GET {{BaseURL}}/api/events/search
GET {{BaseURL}}/api/free-enterprise/license
GET {{BaseURL}}/api/plugins/org.graylog.enterprise.integrations/office365/checkSubscriptions
GET {{BaseURL}}/api/plugins/org.graylog.enterprise.integrations/office365/inputs
GET {{BaseURL}}/api/plugins/org.graylog.enterprise.integrations/office365/startSubscription
GET {{BaseURL}}/api/plugins/org.graylog.integrations/aws/cloudwatch/log_groups
GET {{BaseURL}}/api/plugins/org.graylog.integrations/aws/inputs
GET {{BaseURL}}/api/plugins/org.graylog.integrations/aws/kinesis/auto_setup/create_stream
GET {{BaseURL}}/api/plugins/org.graylog.integrations/aws/kinesis/auto_setup/create_subscription
GET {{BaseURL}}/api/plugins/org.graylog.integrations/aws/kinesis/auto_setup/create_subscription_policy
GET {{BaseURL}}/api/plugins/org.graylog.integrations/aws/kinesis/health_check
GET {{BaseURL}}/api/plugins/org.graylog.integrations/aws/kinesis/streams
GET {{BaseURL}}/api/plugins/org.graylog.plugins.archive/archives/catalog/rebuild
GET {{BaseURL}}/api/plugins/org.graylog.plugins.archive/backends
GET {{BaseURL}}/api/plugins/org.graylog.plugins.archive/cluster/archives/catalog/rebuild
GET {{BaseURL}}/api/plugins/org.graylog.plugins.collector/configurations
GET {{BaseURL}}/api/plugins/org.graylog.plugins.license/licenses/verify
GET {{BaseURL}}/api/plugins/org.graylog.plugins.report/reports
GET {{BaseURL}}/api/plugins/org.graylog.plugins.security/team-sync/test/backend
GET {{BaseURL}}/api/plugins/org.graylog.plugins.security/teams
GET {{BaseURL}}/api/scheduler/jobs
GET {{BaseURL}}/api/system/authentication/services/backends
GET {{BaseURL}}/api/system/authentication/services/test/backend/connection
GET {{BaseURL}}/api/system/authentication/services/test/backend/login
GET {{BaseURL}}/api/system
GET {{BaseURL}}/api/system/content_packs
GET {{BaseURL}}/api/system/indexer/cluster/health
GET {{BaseURL}}/api/system/indexer/cluster/name
GET {{BaseURL}}/api/system/debug/events/cluster
GET {{BaseURL}}/api/system/debug/events/local
GET {{BaseURL}}/api/system/jobs
GET {{BaseURL}}/api/system/pipelines/pipeline
GET {{BaseURL}}/api/system/pipelines/rule
GET {{BaseURL}}/api/system/urlwhitelist/check
GET {{BaseURL}}/api/system/urlwhitelist/generate_regex
GET {{BaseURL}}/api/views
GET {{BaseURL}}/api/views/fields
GET {{BaseURL}}/api/views/forValue
GET {{BaseURL}}/api/views/search/messages
GET {{BaseURL}}/api/views/search/metadata
GET {{BaseURL}}/api/views/search/sync
GET {{BaseURL}}/api/users
```

