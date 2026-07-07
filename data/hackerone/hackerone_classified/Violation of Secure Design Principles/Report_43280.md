# HackerOne Report: HTTPS is not enforced for objects stored by HackerOne on Amazon S3
**Report ID:** 43280
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
SSL is not enforced for objects stored by HackerOne on Amazon S3. Currently I see all the screenshots uploaded are stored in Amazon S3 bucket "hackerone-attachments" and by default HTTPS connection is made. However even HTTP connections are open to these URLs indicating that SSL is not enforced by HackerOne on these buckets.

Steps to reproduce:
1. Submit a vulnerability on any program and upload a screenshot. 
2. The URL of the screenshot looks like this:
https://hackerone-attachments.s3.amazonaws.com/production/<some_unique_path>/<filename>
3. Access the same without HTTPS.
http://hackerone-attachments.s3.amazonaws.com/production/<some_unique_path>/<filename>


Proposed Solution:
Always Force SSL on Amazon buckets and deny any HTTP request. This can be done by following these instructions here:
http://stackoverflow.com/questions/21087474/force-ssl-on-amazon-s3

## Discussion & Remediation Timeline
