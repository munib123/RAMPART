# HackerOne Report: Strict Transport Security on secret.ly
**Report ID:** 1498
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Bug: Strict Transport Security.
Description: The application was not sending the Strict-Transport-Security header.

This header is used to force browsers to connect to the application trough a SSL connection.

Impact:
If the connections to the web application are not encrypted, an eavesdropper may be able to wiretap them and obtain any confidential information that is sent between the browser and the server.

References:
url: https://www.secret.ly/

Solution:
The web server should send the Strict Transport Security header along with every response.



## Discussion & Remediation Timeline
