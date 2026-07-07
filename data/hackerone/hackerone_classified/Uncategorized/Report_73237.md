# HackerOne Report: Buffer Over flow when parsing tar/zip/phar in phar_set_inode
**Report ID:** 73237
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
https://bugs.php.net/bug.php?id=69441

Multiple stack-based buffer overflows in the phar_set_inode function in phar_internal.h in PHP before 5.4.40, 5.5.x before 5.5.24, and 5.6.x before 5.6.8 allow remote attackers to execute arbitrary code via a crafted length value in a (1) tar, (2) phar, or (3) ZIP archive.

## Discussion & Remediation Timeline
