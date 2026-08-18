# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 4811_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4811_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 585-625 of the vulnerable file.

	if (error < 0)
		return error;

	GITERR_CHECK_VERSION(t->io, GIT_STREAM_VERSION, "git_stream");

	if (git_stream_supports_proxy(t->io) &&
	    !git_remote__get_http_proxy(t->owner->owner, !!t->connection_data.use_ssl, &proxy_url)) {
		error = git_stream_set_proxy(t->io, proxy_url);
		git__free(proxy_url);

		if (error < 0)
			return error;
	}

	error = git_stream_connect(t->io);

#if defined(GIT_OPENSSL) || defined(GIT_SECURE_TRANSPORT) || defined(GIT_CURL)
	if ((!error || error == GIT_ECERTIFICATE) && t->owner->certificate_check_cb != NULL &&
	    git_stream_is_encrypted(t->io)) {
		git_cert *cert;
		int is_valid;

		if ((error = git_stream_certificate(&cert, t->io)) < 0)
			return error;

		giterr_clear();
		is_valid = error != GIT_ECERTIFICATE;
		error = t->owner->certificate_check_cb(cert, is_valid, t->connection_data.host, t->owner->message_cb_payload);

		if (error < 0) {
			if (!giterr_last())
				giterr_set(GITERR_NET, "user cancelled certificate check");

			return error;
		}
	}
#endif
	if (error < 0)
		return error;

	t->connected = 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -602,13 +602,12 @@
 	if ((!error || error == GIT_ECERTIFICATE) && t->owner->certificate_check_cb != NULL &&
 	    git_stream_is_encrypted(t->io)) {
 		git_cert *cert;
-		int is_valid;
+		int is_valid = (error == GIT_OK);
 
 		if ((error = git_stream_certificate(&cert, t->io)) < 0)
 			return error;
 
 		giterr_clear();
-		is_valid = error != GIT_ECERTIFICATE;
 		error = t->owner->certificate_check_cb(cert, is_valid, t->connection_data.host, t->owner->message_cb_payload);
 
 		if (error < 0) {
```
