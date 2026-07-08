# Vulnerability: Azure VMSS Health Monitoring Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vmss-health-monitoring-missing.yaml`)

## Description
Ensure that Monitor Application Health feature is enabled for all the instances running within your Azure virtual machine scale set. Health monitoring via Application Health extension is required for OS upgrades and automatic instance repairs. The Azure Application Health extension reports on the application health from inside the virtual machine scale set instances. You can configure the health extension to probe on an application endpoint and update the status of the application on that instance. This status is checked by Microsoft Azure to determine whether the instance is eligible for upgrade or repair operations.

## Secure Mitigation
Enable the Application Health extension in your Azure VMSS instances to ensure continuous health monitoring and eligibility for necessary upgrades and repairs.

