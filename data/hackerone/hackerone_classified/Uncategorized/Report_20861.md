# HackerOne Report: moderate: mod_deflate denial of service
**Report ID:** 20861
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
A resource consumption flaw was found in mod_deflate. If request body decompression was configured (using the "DEFLATE" input filter), a remote attacker could cause the server to consume significant memory and/or CPU resources. The use of request body decompression is not a common configuration.

Acknowledgements: This issue was reported by Giancarlo Pellegrino and Davide Balzarotti

Resolved in Apache httpd 2.4.10-dev: http://httpd.apache.org/security/vulnerabilities_24.html


## Discussion & Remediation Timeline
