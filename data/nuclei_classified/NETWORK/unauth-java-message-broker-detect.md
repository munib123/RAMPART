# Vulnerability: Unauthenticated Java Message Broker - Detect
**Classification:** NETWORK
**Source:** Nuclei Template (`unauth-java-message-broker-detect.yaml`)

## Description
Detection of a Java Message Service (JMS) broker, typically used by Oracle GlassFish Message Queue and Payara Application Server. This port should remain closed to the internet, as it enables unauthenticated access to messaging services.

