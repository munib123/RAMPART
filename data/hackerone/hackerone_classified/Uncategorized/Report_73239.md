# HackerOne Report: ZIP Integer Overflow leads to writing past heap boundary
**Report ID:** 73239
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
https://bugs.php.net/bug.php?id=69253

Integer overflow in the _zip_cdir_new function in zip_dirent.c in libzip 0.11.2 and earlier, as used in the ZIP extension in PHP before 5.4.39, 5.5.x before 5.5.23, and 5.6.x before 5.6.7 and other products, allows remote attackers to cause a denial of service (application crash) or possibly execute arbitrary code via a ZIP archive that contains many entries, leading to a heap-based buffer overflow.

## Discussion & Remediation Timeline
