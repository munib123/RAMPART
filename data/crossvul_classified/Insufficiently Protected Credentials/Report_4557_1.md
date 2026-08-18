# CrossVul Fix Pair: Insufficiently Protected Credentials in shell
**Pair ID:** 4557_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4557_1`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```bash
Lines 292-312 of the vulnerable file.

test_expect_success 'helpers can abort the process' '
	test_must_fail git \
		-c credential.helper="!f() { echo quit=1; }; f" \
		-c credential.helper="verbatim foo bar" \
		credential fill >stdout &&
	>expect &&
	test_cmp expect stdout
'

test_expect_success 'empty helper spec resets helper list' '
	test_config credential.helper "verbatim file file" &&
	check fill "" "verbatim cmdline cmdline" <<-\EOF
	--
	username=cmdline
	password=cmdline
	--
	verbatim: get
	EOF
'

test_done
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -309,4 +309,10 @@
 	EOF
 '
 
+test_expect_success 'url parser rejects embedded newlines' '
+	test_must_fail git credential fill <<-\EOF
+	url=https://one.example.com?%0ahost=two.example.com/
+	EOF
+'
+
 test_done
```
