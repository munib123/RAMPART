# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5561_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5561_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 24-64 of the vulnerable file.

#include <crm/cib.h>
#include <crm/common/xml.h>
#include <crm/cluster.h>
#include <crm/common/mainloop.h>
#ifdef HAVE_GNUTLS_GNUTLS_H
#  undef KEYFILE
#  include <gnutls/gnutls.h>
#endif


extern gboolean cib_is_master;
extern GHashTable *client_list;
extern GHashTable *peer_hash;
extern GHashTable *config_hash;

typedef struct cib_client_s {
    char *id;
    char *name;
    char *callback_id;
    char *user;
    int request_id;

    qb_ipcs_connection_t *ipc;

#ifdef HAVE_GNUTLS_GNUTLS_H
    gnutls_session *session;
#else
    void *session;
#endif
    gboolean encrypted;
    mainloop_io_t *remote;
        
    unsigned long num_calls;

    int pre_notify;
    int post_notify;
    int confirmations;
    int replace;
    int diffs;

    GList *delegated_calls;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,18 +41,21 @@
     char *name;
     char *callback_id;
     char *user;
+    char *recv_buf;
     int request_id;
 
     qb_ipcs_connection_t *ipc;
 
 #ifdef HAVE_GNUTLS_GNUTLS_H
     gnutls_session *session;
+    gboolean handshake_complete;
 #else
     void *session;
 #endif
     gboolean encrypted;
+    gboolean remote_auth;
     mainloop_io_t *remote;
-        
+
     unsigned long num_calls;
 
     int pre_notify;
@@ -60,6 +63,7 @@
     int confirmations;
     int replace;
     int diffs;
+    int remote_auth_timeout;
 
     GList *delegated_calls;
 } cib_client_t;
```
