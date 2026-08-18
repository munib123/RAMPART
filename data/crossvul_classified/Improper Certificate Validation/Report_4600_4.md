# CrossVul Fix Pair: Improper Certificate Validation in shell
**Pair ID:** 4600_4
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4600_4`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```bash
Lines 1-12 of the vulnerable file.

#!/bin/bash
# Copyright (C) 2015 Adrien Vergé

rc=0

./tests/lint/eol-at-eof.sh $(git ls-files) || rc=1

./tests/lint/line_length.py $(git ls-files '*.[ch]') || rc=1

./tests/lint/astyle.sh $(git ls-files '*.[ch]') || rc=1

exit $rc
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,10 +3,10 @@
 
 rc=0
 
-./tests/lint/eol-at-eof.sh $(git ls-files) || rc=1
+./tests/lint/eol-at-eof.sh $(git ls-files | grep -v openssl_hostname_validation) || rc=1
 
-./tests/lint/line_length.py $(git ls-files '*.[ch]') || rc=1
+./tests/lint/line_length.py $(git ls-files '*.[ch]' | grep -v openssl_hostname_validation) || rc=1
 
-./tests/lint/astyle.sh $(git ls-files '*.[ch]') || rc=1
+./tests/lint/astyle.sh $(git ls-files '*.[ch]' | grep -v openssl_hostname_validation) || rc=1
 
 exit $rc
```
