# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 2374_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2374_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 1-27 of the vulnerable file.

/* -*- mode: c; c-file-style: "bsd"; indent-tabs-mode: t -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 */

#include <k5-platform.h>
#include <gssrpc/rpc.h>
#include <gssapi/gssapi_krb5.h> /* for gss_nt_krb5_name */
#include <syslog.h>
#include <kadm5/kadm_rpc.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <adm_proto.h>
#include "misc.h"
#include "kadm5/server_internal.h"

extern void *global_server_handle;

static int check_rpcsec_auth(struct svc_req *);

/*
 * Function: kadm_1
 *
 * Purpose: RPC proccessing procedure.
 *	    originally generated from rpcgen
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,7 @@
  *
  */
 
-#include <k5-platform.h>
+#include <k5-int.h>
 #include <gssrpc/rpc.h>
 #include <gssapi/gssapi_krb5.h> /* for gss_nt_krb5_name */
 #include <syslog.h>
@@ -296,14 +296,8 @@
      c1 = krb5_princ_component(kctx, princ, 0);
      c2 = krb5_princ_component(kctx, princ, 1);
      realm = krb5_princ_realm(kctx, princ);
-     if (strncmp(handle->params.realm, realm->data, realm->length) == 0
-	 && strncmp("kadmin", c1->data, c1->length) == 0) {
-
-	  if (strncmp("history", c2->data, c2->length) == 0)
-	       goto fail_princ;
-	  else
-	       success = 1;
-     }
+     success = data_eq_string(*realm, handle->params.realm) &&
+	     data_eq_string(*c1, "kadmin") && !data_eq_string(*c2, "history");
 
 fail_princ:
      if (!success) {
```
