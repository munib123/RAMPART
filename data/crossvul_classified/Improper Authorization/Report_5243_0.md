# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5243_0
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5243_0`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 276-316 of the vulnerable file.

        return;
    }

    c = qb_ipcs_connection_first_get(service);

    while (c != NULL) {
        qb_ipcs_connection_t *last = c;

        c = qb_ipcs_connection_next_get(service, last);

        /* There really shouldn't be anyone connected at this point */
        crm_notice("Disconnecting client %p, pid=%d...", last, crm_ipcs_client_pid(last));
        qb_ipcs_disconnect(last);
        qb_ipcs_connection_unref(last);
    }
}

crm_client_t *
crm_client_new(qb_ipcs_connection_t * c, uid_t uid_client, gid_t gid_client)
{
    static uid_t uid_server = 0;
    static gid_t gid_cluster = 0;

    crm_client_t *client = NULL;

    CRM_LOG_ASSERT(c);
    if (c == NULL) {
        return NULL;
    }

    if (gid_cluster == 0) {
        uid_server = getuid();
        if(crm_user_lookup(CRM_DAEMON_USER, NULL, &gid_cluster) < 0) {
            static bool have_error = FALSE;
            if(have_error == FALSE) {
                crm_warn("Could not find group for user %s", CRM_DAEMON_USER);
                have_error = TRUE;
            }
        }
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -293,7 +293,6 @@
 crm_client_t *
 crm_client_new(qb_ipcs_connection_t * c, uid_t uid_client, gid_t gid_client)
 {
-    static uid_t uid_server = 0;
     static gid_t gid_cluster = 0;
 
     crm_client_t *client = NULL;
@@ -304,7 +303,6 @@
     }
 
     if (gid_cluster == 0) {
-        uid_server = getuid();
         if(crm_user_lookup(CRM_DAEMON_USER, NULL, &gid_cluster) < 0) {
             static bool have_error = FALSE;
             if(have_error == FALSE) {
@@ -314,16 +312,10 @@
         }
     }
 
-    if(gid_cluster != 0 && gid_client != 0) {
-        uid_t best_uid = -1; /* Passing -1 to chown(2) means don't change */
-
-        if(uid_client == 0 || uid_server == 0) { /* Someone is priveliged, but the other may not be */
-            best_uid = QB_MAX(uid_client, uid_server);
-            crm_trace("Allowing user %u to clean up after disconnect", best_uid);
-        }
-
+    if (uid_client != 0) {
         crm_trace("Giving access to group %u", gid_cluster);
-        qb_ipcs_connection_auth_set(c, best_uid, gid_cluster, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
+        /* Passing -1 to chown(2) means don't change */
+        qb_ipcs_connection_auth_set(c, -1, gid_cluster, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
     }
 
     crm_client_init();
```
