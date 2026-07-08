# Vulnerability: Interactive Serial Console Support Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-serial-console-enabled.yaml`)

## Description
Ensure that "Enable connecting to serial ports" configuration setting is disabled for all your production Google Compute Engine instances. The interactive serial console does not support IP-based access restrictions such as IP address whitelists. If enabled, clients can attempt to connect to your instance from any IP address if they know the username, SSH key, project ID, instance name and zone.

## Secure Mitigation
Disable interactive serial console support by setting the "serial-port-enable" metadata key to "false" for your VM instances to prevent unauthorized access through serial ports.

