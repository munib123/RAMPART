# HackerOne Report: List of devices is accessible regardless of the account limitations
**Report ID:** 97535
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
List of devices is accessible regardless of the account limitations.

**PoC**

. Create a limited account A with no rights.
. Log some devices with a different account B.
. From account A, GET /admin/mobile_devices.json.
. List of devices.

## Discussion & Remediation Timeline
