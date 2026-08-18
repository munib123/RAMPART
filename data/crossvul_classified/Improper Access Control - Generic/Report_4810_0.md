# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 4810_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4810_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 607-647 of the vulnerable file.

	} else {
#ifdef GIT_CURL
		error = git_curl_stream_new(&t->io, t->connection_data.host, t->connection_data.port);
#else
		error = git_socket_stream_new(&t->io,  t->connection_data.host, t->connection_data.port);
#endif
	}

	if (error < 0)
		return error;

	GITERR_CHECK_VERSION(t->io, GIT_STREAM_VERSION, "git_stream");

	apply_proxy_config(t);

	error = git_stream_connect(t->io);

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

	if (error < 0)
		return error;

	t->connected = 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -624,13 +624,12 @@
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
