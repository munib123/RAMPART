# CrossVul Fix Pair: Insufficiently Protected Credentials in shell
**Pair ID:** 3894_2
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** shell
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3894_2`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```bash
Lines 293-337 of the vulnerable file.

	check_language "ko-KR, en-US;q=0.9, *;q=0.8" "ko_KR::en_US" &&
	check_language "ko-KR, *;q=0.9" ":::ko_KR" &&
	check_language "ko-KR, en-US;q=0.9, *;q=0.8" "ko_KR!!:en_US" &&
	check_language "ko-KR, ja-JP;q=0.9, *;q=0.8" "ko_KR en_US:ja_JP"'

test_expect_success 'git client sends Accept-Language with many preferred languages' '
	check_language "ko-KR, en-US;q=0.9, fr-CA;q=0.8, de;q=0.7, sr;q=0.6, \
ja;q=0.5, zh;q=0.4, sv;q=0.3, pt;q=0.2, *;q=0.1" \
		ko_KR.EUC-KR:en_US.UTF-8:fr_CA:de.UTF-8@euro:sr@latin:ja:zh:sv:pt &&
	check_language "ko-KR, en-US;q=0.99, fr-CA;q=0.98, de;q=0.97, sr;q=0.96, \
ja;q=0.95, zh;q=0.94, sv;q=0.93, pt;q=0.92, nb;q=0.91, *;q=0.90" \
		ko_KR.EUC-KR:en_US.UTF-8:fr_CA:de.UTF-8@euro:sr@latin:ja:zh:sv:pt:nb
'

test_expect_success 'git client does not send an empty Accept-Language' '
	GIT_TRACE_CURL=true LANGUAGE= git ls-remote "$HTTPD_URL/dumb/repo.git" 2>stderr &&
	! grep "^=> Send header: Accept-Language:" stderr
'

test_expect_success 'remote-http complains cleanly about malformed urls' '
	# do not actually issue "list" or other commands, as we do not
	# want to rely on what curl would actually do with such a broken
	# URL. This is just about making sure we do not segfault during
	# initialization.
	test_must_fail git remote-http http::/example.com/repo.git
'

test_expect_success 'redirects can be forbidden/allowed' '
	test_must_fail git -c http.followRedirects=false \
		clone $HTTPD_URL/dumb-redir/repo.git dumb-redir &&
	git -c http.followRedirects=true \
		clone $HTTPD_URL/dumb-redir/repo.git dumb-redir 2>stderr
'

test_expect_success 'redirects are reported to stderr' '
	# just look for a snippet of the redirected-to URL
	test_i18ngrep /dumb/ stderr
'

test_expect_success 'non-initial redirects can be forbidden' '
	test_must_fail git -c http.followRedirects=initial \
		clone $HTTPD_URL/redir-objects/repo.git redir-objects &&
	git -c http.followRedirects=true \
		clone $HTTPD_URL/redir-objects/repo.git redir-objects
'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -310,11 +310,8 @@
 '
 
 test_expect_success 'remote-http complains cleanly about malformed urls' '
-	# do not actually issue "list" or other commands, as we do not
-	# want to rely on what curl would actually do with such a broken
-	# URL. This is just about making sure we do not segfault during
-	# initialization.
-	test_must_fail git remote-http http::/example.com/repo.git
+	test_must_fail git remote-http http::/example.com/repo.git 2>stderr &&
+	test_i18ngrep "url has no scheme" stderr
 '
 
 test_expect_success 'redirects can be forbidden/allowed' '
```
