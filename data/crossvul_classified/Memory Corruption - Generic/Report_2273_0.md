# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2273_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2273_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-36 of the vulnerable file.


#include <linux/ceph/ceph_debug.h>

#include <linux/err.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>

#include <linux/ceph/decode.h>
#include <linux/ceph/auth.h>

#include "crypto.h"
#include "auth_x.h"
#include "auth_x_protocol.h"

#define TEMP_TICKET_BUF_LEN	256

static void ceph_x_validate_tickets(struct ceph_auth_client *ac, int *pneed);

static int ceph_x_is_authenticated(struct ceph_auth_client *ac)
{
	struct ceph_x_info *xi = ac->private;
	int need;

	ceph_x_validate_tickets(ac, &need);
	dout("ceph_x_is_authenticated want=%d need=%d have=%d\n",
	     ac->want_keys, need, xi->have_keys);
	return (ac->want_keys & xi->have_keys) == ac->want_keys;
}

static int ceph_x_should_authenticate(struct ceph_auth_client *ac)
{
	struct ceph_x_info *xi = ac->private;
	int need;

	ceph_x_validate_tickets(ac, &need);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -12,8 +12,6 @@
 #include "crypto.h"
 #include "auth_x.h"
 #include "auth_x_protocol.h"
-
-#define TEMP_TICKET_BUF_LEN	256
 
 static void ceph_x_validate_tickets(struct ceph_auth_client *ac, int *pneed);
 
@@ -64,7 +62,7 @@
 }
 
 static int ceph_x_decrypt(struct ceph_crypto_key *secret,
-			  void **p, void *end, void *obuf, size_t olen)
+			  void **p, void *end, void **obuf, size_t olen)
 {
 	struct ceph_x_encrypt_header head;
 	size_t head_len = sizeof(head);
@@ -75,8 +73,14 @@
 		return -EINVAL;
 
 	dout("ceph_x_decrypt len %d\n", len);
-	ret = ceph_decrypt2(secret, &head, &head_len, obuf, &olen,
-			    *p, len);
+	if (*obuf == NULL) {
+		*obuf = kmalloc(len, GFP_NOFS);
+		if (!*obuf)
+			return -ENOMEM;
+		olen = len;
+	}
+
+	ret = ceph_decrypt2(secret, &head, &head_len, *obuf, &olen, *p, len);
 	if (ret)
 		return ret;
 	if (head.struct_v != 1 || le64_to_cpu(head.magic) != CEPHX_ENC_MAGIC)
@@ -131,18 +135,19 @@
 
 static int process_one_ticket(struct ceph_auth_client *ac,
 			      struct ceph_crypto_key *secret,
-			      void **p, void *end,
-			      void *dbuf, void *ticket_buf)
+			      void **p, void *end)
 {
 	struct ceph_x_info *xi = ac->private;
 	int type;
 	u8 tkt_struct_v, blob_struct_v;
 	struct ceph_x_ticket_handler *th;
+	void *dbuf = NULL;
 	void *dp, *dend;
 	int dlen;
 	char is_enc;
 	struct timespec validity;
 	struct ceph_crypto_key old_key;
+	void *ticket_buf = NULL;
 	void *tp, *tpend;
 	struct ceph_timespec new_validity;
 	struct ceph_crypto_key new_session_key;
@@ -167,8 +172,7 @@
 	}
 
 	/* blob for me */
-	dlen = ceph_x_decrypt(secret, p, end, dbuf,
-			      TEMP_TICKET_BUF_LEN);
+	dlen = ceph_x_decrypt(secret, p, end, &dbuf, 0);
 	if (dlen <= 0) {
 		ret = dlen;
 		goto out;
@@ -195,20 +199,25 @@
 
 	/* ticket blob for service */
 	ceph_decode_8_safe(p, end, is_enc, bad);
-	tp = ticket_buf;
 	if (is_enc) {
 		/* encrypted */
 		dout(" encrypted ticket\n");
-		dlen = ceph_x_decrypt(&old_key, p, end, ticket_buf,
-				      TEMP_TICKET_BUF_LEN);
+		dlen = ceph_x_decrypt(&old_key, p, end, &ticket_buf, 0);
 		if (dlen < 0) {
 			ret = dlen;
 			goto out;
 		}
+		tp = ticket_buf;
 		dlen = ceph_decode_32(&tp);
 	} else {
 		/* unencrypted */
 		ceph_decode_32_safe(p, end, dlen, bad);
+		ticket_buf = kmalloc(dlen, GFP_NOFS);
+		if (!ticket_buf) {
+			ret = -ENOMEM;
+			goto out;
+		}
+		tp = ticket_buf;
 		ceph_decode_need(p, end, dlen, bad);
 		ceph_decode_copy(p, ticket_buf, dlen);
 	}
@@ -237,6 +246,8 @@
 	xi->have_keys |= th->service;
 
 out:
+	kfree(ticket_buf);
+	kfree(dbuf);
 	return ret;
 
 bad:
@@ -249,21 +260,10 @@
 				    void *buf, void *end)
 {
 	void *p = buf;
-	char *dbuf;
-	char *ticket_buf;
 	u8 reply_struct_v;
 	u32 num;
 	int ret;
 
-	dbuf = kmalloc(TEMP_TICKET_BUF_LEN, GFP_NOFS);
-	if (!dbuf)
-		return -ENOMEM;
-
-	ret = -ENOMEM;
-	ticket_buf = kmalloc(TEMP_TICKET_BUF_LEN, GFP_NOFS);
-	if (!ticket_buf)
-		goto out_dbuf;
-
 	ceph_decode_8_safe(&p, end, reply_struct_v, bad);
 	if (reply_struct_v != 1)
 		return -EINVAL;
@@ -272,22 +272,15 @@
 	dout("%d tickets\n", num);
 
 	while (num--) {
-		ret = process_one_ticket(ac, secret, &p, end,
-					 dbuf, ticket_buf);
+		ret = process_one_ticket(ac, secret, &p, end);
 		if (ret)
-			goto out;
-	}
-
-	ret = 0;
-out:
-	kfree(ticket_buf);
-out_dbuf:
-	kfree(dbuf);
-	return ret;
+			return ret;
+	}
+
+	return 0;
 
 bad:
-	ret = -EINVAL;
-	goto out;
+	return -EINVAL;
 }
 
 static int ceph_x_build_authorizer(struct ceph_auth_client *ac,
@@ -603,13 +596,14 @@
 	struct ceph_x_ticket_handler *th;
 	int ret = 0;
 	struct ceph_x_authorize_reply reply;
+	void *preply = &reply;
 	void *p = au->reply_buf;
 	void *end = p + sizeof(au->reply_buf);
 
 	th = get_ticket_handler(ac, au->service);
 	if (IS_ERR(th))
 		return PTR_ERR(th);
-	ret = ceph_x_decrypt(&th->session_key, &p, end, &reply, sizeof(reply));
+	ret = ceph_x_decrypt(&th->session_key, &p, end, &preply, sizeof(reply));
 	if (ret < 0)
 		return ret;
 	if (ret != sizeof(reply))
```
