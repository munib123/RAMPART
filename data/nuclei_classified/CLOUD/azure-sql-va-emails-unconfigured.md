# Vulnerability: Azure SQL Classic VA Emails Unconfigured
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-sql-va-emails-unconfigured.yaml`)

## Description
Ensure that your Amazon SQL database servers are configured with the email addresses of the concerned data owners, admins or stakeholders in order to receive Vulnerability Assessment (VA) scan reports and alerts for critical events. This setting is only available for SQL servers using the classic SQL Vulnerability Assessment configuration. For new, express configuration, email notifications are enabled by default and cannot be customized.

## Secure Mitigation
Configure the email addresses for vulnerability assessment notifications in your SQL server settings to ensure alerts and reports are received by the appropriate stakeholders.

