# CrossVul Fix Pair: Insufficiently Protected Credentials in shell
**Pair ID:** 3894_3
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3894_3`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```bash
Lines 43-83 of the vulnerable file.

	git init --bare dst &&
	git -C dst config transfer.fsckObjects true &&
	test_must_fail git push dst HEAD 2>err &&
	grep gitmodulesUrl err
'

test_expect_success 'trailing backslash is handled correctly' '
	git init testmodule &&
	test_commit -C testmodule c &&
	git submodule add ./testmodule &&
	: ensure that the name ends in a double backslash &&
	sed -e "s|\\(submodule \"testmodule\\)\"|\\1\\\\\\\\\"|" \
		-e "s|url = .*|url = \" --should-not-be-an-option\"|" \
		<.gitmodules >.new &&
	mv .new .gitmodules &&
	git commit -am "Add testmodule" &&
	test_must_fail git clone --verbose --recurse-submodules . dolly 2>err &&
	test_i18ngrep ! "unknown option" err
'

test_expect_success 'fsck permits embedded newline with unrecognized scheme' '
	git checkout --orphan newscheme &&
	cat >.gitmodules <<-\EOF &&
	[submodule "foo"]
		url = "data://acjbkd%0akajfdickajkd"
	EOF
	git add .gitmodules &&
	git commit -m "gitmodules with unrecognized scheme" &&
	test_when_finished "rm -rf dst" &&
	git init --bare dst &&
	git -C dst config transfer.fsckObjects true &&
	git push dst HEAD
'

test_expect_success 'fsck rejects embedded newline in url' '
	# create an orphan branch to avoid existing .gitmodules objects
	git checkout --orphan newline &&
	cat >.gitmodules <<-\EOF &&
	[submodule "foo"]
	url = "https://one.example.com?%0ahost=two.example.com/foo.git"
	EOF
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,6 +60,38 @@
 	test_i18ngrep ! "unknown option" err
 '
 
+test_expect_success 'fsck rejects missing URL scheme' '
+	git checkout --orphan missing-scheme &&
+	cat >.gitmodules <<-\EOF &&
+	[submodule "foo"]
+		url = http::one.example.com/foo.git
+	EOF
+	git add .gitmodules &&
+	test_tick &&
+	git commit -m "gitmodules with missing URL scheme" &&
+	test_when_finished "rm -rf dst" &&
+	git init --bare dst &&
+	git -C dst config transfer.fsckObjects true &&
+	test_must_fail git push dst HEAD 2>err &&
+	grep gitmodulesUrl err
+'
+
+test_expect_success 'fsck rejects relative URL resolving to missing scheme' '
+	git checkout --orphan relative-missing-scheme &&
+	cat >.gitmodules <<-\EOF &&
+	[submodule "foo"]
+		url = "..\\../.\\../:one.example.com/foo.git"
+	EOF
+	git add .gitmodules &&
+	test_tick &&
+	git commit -m "gitmodules with relative URL that strips off scheme" &&
+	test_when_finished "rm -rf dst" &&
+	git init --bare dst &&
+	git -C dst config transfer.fsckObjects true &&
+	test_must_fail git push dst HEAD 2>err &&
+	grep gitmodulesUrl err
+'
+
 test_expect_success 'fsck permits embedded newline with unrecognized scheme' '
 	git checkout --orphan newscheme &&
 	cat >.gitmodules <<-\EOF &&
```
