# Vulnerability: Unrestricted API Key Usage
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-api-key-unrestricted.yaml`)

## Description
Ensure that the use of Google Cloud API keys is limited to trusted and reliable hosts, HTTP referrers, or applications. An API key application restriction manages the authorization of websites, IP addresses, or Android/iOS mobile applications that can employ your API key. It is crucial that all API keys used in production employ host and application restrictions. By enforcing these restrictions, you can reduce the impact that a compromised API key can have on your applications.

## Secure Mitigation
Apply restrictions to all production API keys to specify the allowed websites, IP addresses, or mobile applications that can use each key, to mitigate potential abuse.

