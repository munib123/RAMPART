# Vulnerability: DoS Vulnerable Service Enabled
**Classification:** LOCAL
**Source:** Nuclei Template (`linux-legacy-services-enabled.yaml`)

## Description
Services such as echo, discard, daytime, and chargen were enabled on the system, allowing attackers to exploit them to extract system information or launch denial-of-service (DoS) attacks.These legacy services were required to be disabled unless explicitly needed.

