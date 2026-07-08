# Vulnerability: Installation of Unsigned Kernel-Mode Drivers Allowed
**Classification:** DRIVERS
**Source:** Nuclei Template (`unsigned-kernel-mode-drivers-allowed.yaml`)

## Description
Checks if the system allows installation of unsigned kernel-mode drivers, which can be malicious.

## Secure Mitigation
Restrict the installation of unsigned drivers by enforcing driver signature checks.

