# CrossVul Fix Pair: Improper Input Validation in shell
**Pair ID:** 396_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `396_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```bash
Lines 1-20 of the vulnerable file.

#!/bin/sh

test_description='check handling of .gitmodule path with dash'
. ./test-lib.sh

test_expect_success 'create submodule with dash in path' '
	git init upstream &&
	git -C upstream commit --allow-empty -m base &&
	git submodule add ./upstream sub &&
	git mv sub ./-sub &&
	git commit -m submodule
'

test_expect_success 'clone rejects unprotected dash' '
	test_when_finished "rm -rf dst" &&
	git clone --recurse-submodules . dst 2>err &&
	test_i18ngrep ignoring err
'

test_done
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,4 +17,12 @@
 	test_i18ngrep ignoring err
 '
 
+test_expect_success 'fsck rejects unprotected dash' '
+	test_when_finished "rm -rf dst" &&
+	git init --bare dst &&
+	git -C dst config transfer.fsckObjects true &&
+	test_must_fail git push dst HEAD 2>err &&
+	grep gitmodulesPath err
+'
+
 test_done
```
