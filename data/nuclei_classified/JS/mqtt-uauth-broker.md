# Vulnerability: MQTT Unauthenticated Broker - Detect
**Classification:** JS
**Source:** Nuclei Template (`mqtt-uauth-broker.yaml`)

## Description
Detects an unauthenticated MQTT broker and attempts to subscribe to the $SYS/# topic to enumerate broker and system information.

