# Vulnerability: API Keys Should Only Exist for Active Services
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-api-keys-inactive-services.yaml`)

## Description
Ensure that your Google Cloud projects are using the standard authentication flow as the preferred method for authentication, rather than relying on API keys. API keys are simple encrypted strings that can be used when calling certain APIs which don't need to access private user data. API keys should be exclusively employed for active services when alternative authentication methods are not accessible, otherwise deleted.

## Secure Mitigation
Review and ensure that API keys are only configured for active services. Delete or disable API keys associated with inactive or unnecessary services to minimize security risks.

