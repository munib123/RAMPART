# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2964_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2964_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 2215-2255 of the vulnerable file.

			    &skey->key, r->client->entry.kvno,
			    &r->reply_key, 0, &r->e_text, reply);
    if (ret)
	goto out;

    /*
     * Check if message too large
     */
    if (datagram_reply && reply->length > config->max_datagram_reply_length) {
	krb5_data_free(reply);
	ret = KRB5KRB_ERR_RESPONSE_TOO_BIG;
	_kdc_set_e_text(r, "Reply packet too large");
    }

out:
    free_AS_REP(&rep);

    /*
     * In case of a non proxy error, build an error message.
     */
    if(ret != 0 && ret != HDB_ERR_NOT_FOUND_HERE && reply->length == 0) {
	ret = _kdc_fast_mk_error(context, r,
				 &error_method,
				 r->armor_crypto,
				 &req->req_body,
				 ret, r->e_text,
				 r->server_princ,
				 &r->client_princ->name,
				 &r->client_princ->realm,
				 NULL, NULL,
				 reply);
	if (ret)
	    goto out2;
    }
out2:
    free_EncTicketPart(&r->et);
    free_EncKDCRepPart(&r->ek);
    free_KDCFastState(&r->fast);

    if (error_method.len)
	free_METHOD_DATA(&error_method);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2232,15 +2232,17 @@
     /*
      * In case of a non proxy error, build an error message.
      */
-    if(ret != 0 && ret != HDB_ERR_NOT_FOUND_HERE && reply->length == 0) {
+    if (ret != 0 && ret != HDB_ERR_NOT_FOUND_HERE && reply->length == 0) {
 	ret = _kdc_fast_mk_error(context, r,
 				 &error_method,
 				 r->armor_crypto,
 				 &req->req_body,
 				 ret, r->e_text,
 				 r->server_princ,
-				 &r->client_princ->name,
-				 &r->client_princ->realm,
+				 r->client_princ ?
+                                     &r->client_princ->name : NULL,
+				 r->client_princ ?
+                                     &r->client_princ->realm : NULL,
 				 NULL, NULL,
 				 reply);
 	if (ret)
```
