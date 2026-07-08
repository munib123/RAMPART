# Vulnerability: Shielded VM Security Features Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-shielded-disabled.yaml`)

## Description
Ensure that your Google Compute Engine instances are configured to use Shielded VM security feature for protection against rootkits and bootkits. Google Compute Engine service can enable 3 advanced security components for Shielded VM instances:
- Virtual Trusted Platform Module (vTPM) - validates the guest virtual machine pre-boot and boot integrity, and provides key generation and protection
- Integrity Monitoring - lets you monitor and verify the runtime boot integrity using Google Cloud Operations reports
- Secure boot - protects your VM instances against boot-level and kernel-level malware and rootkits

## Secure Mitigation
Enable Shielded VM security features (vTPM and Integrity Monitoring) for your VM instances. Note that enabling Secure Boot is optional and should only be done if you don't use custom or unsigned drivers, as it may prevent the VM from booting.

