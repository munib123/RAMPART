# CrossVul Fix Pair: Improper Input Validation in shell
**Pair ID:** 397_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `397_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```bash
Lines 3-34 of the vulnerable file.

test_description='check handling of .gitmodule url with dash'
. ./test-lib.sh

test_expect_success 'create submodule with protected dash in url' '
	git init upstream &&
	git -C upstream commit --allow-empty -m base &&
	mv upstream ./-upstream &&
	git submodule add ./-upstream sub &&
	git add sub .gitmodules &&
	git commit -m submodule
'

test_expect_success 'clone can recurse submodule' '
	test_when_finished "rm -rf dst" &&
	git clone --recurse-submodules . dst &&
	echo base >expect &&
	git -C dst/sub log -1 --format=%s >actual &&
	test_cmp expect actual
'

test_expect_success 'remove ./ protection from .gitmodules url' '
	perl -i -pe "s{\./}{}" .gitmodules &&
	git commit -am "drop protection"
'

test_expect_success 'clone rejects unprotected dash' '
	test_when_finished "rm -rf dst" &&
	test_must_fail git clone --recurse-submodules . dst 2>err &&
	test_i18ngrep ignoring err
'

test_done
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,6 +20,13 @@
 	test_cmp expect actual
 '
 
+test_expect_success 'fsck accepts protected dash' '
+	test_when_finished "rm -rf dst" &&
+	git init --bare dst &&
+	git -C dst config transfer.fsckObjects true &&
+	git push dst HEAD
+'
+
 test_expect_success 'remove ./ protection from .gitmodules url' '
 	perl -i -pe "s{\./}{}" .gitmodules &&
 	git commit -am "drop protection"
@@ -31,4 +38,12 @@
 	test_i18ngrep ignoring err
 '
 
+test_expect_success 'fsck rejects unprotected dash' '
+	test_when_finished "rm -rf dst" &&
+	git init --bare dst &&
+	git -C dst config transfer.fsckObjects true &&
+	test_must_fail git push dst HEAD 2>err &&
+	grep gitmodulesUrl err
+'
+
 test_done
```
