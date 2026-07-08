# Vulnerability: Azure Functions with Admin Privileges
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-functionapp-admin-privileges.yaml`)

## Description
Ensure that your functions managed with Microsoft Azure Function App don't have privileged administrative permissions in order to promote the Principle of Least Privilege (POLP) and provide your functions the minimal amount of access required to perform their tasks.

## Secure Mitigation
Review and restrict the roles assigned to function apps to ensure they only have permissions necessary for their operation. Modify the roles through Azure portal or Azure CLI.

