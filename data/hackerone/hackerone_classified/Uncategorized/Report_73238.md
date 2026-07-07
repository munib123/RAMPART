# HackerOne Report: Buffer Over-read in unserialize when parsing Phar
**Report ID:** 73238
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
https://bugs.php.net/bug.php?id=69324

ext/phar/phar.c in PHP before 5.4.40, 5.5.x before 5.5.24, and 5.6.x before 5.6.8 allows remote attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read and application crash) via a crafted length value in conjunction with crafted serialized data in a phar archive, related to the phar_parse_metadata and phar_parse_pharfile functions.

## Discussion & Remediation Timeline
