# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1576_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1576_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 54-94 of the vulnerable file.

#include <stdarg.h>
#endif

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

APR_HOOK_STRUCT(
    APR_HOOK_LINK(translate_name)
    APR_HOOK_LINK(map_to_storage)
    APR_HOOK_LINK(check_user_id)
    APR_HOOK_LINK(fixups)
    APR_HOOK_LINK(type_checker)
    APR_HOOK_LINK(access_checker)
    APR_HOOK_LINK(access_checker_ex)
    APR_HOOK_LINK(auth_checker)
    APR_HOOK_LINK(insert_filter)
    APR_HOOK_LINK(create_request)
    APR_HOOK_LINK(post_perdir_config)
    APR_HOOK_LINK(dirwalk_stat)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int,translate_name,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,map_to_storage,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,check_user_id,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,fixups,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,type_checker,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,access_checker,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,access_checker_ex,
                          (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,auth_checker,
                            (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_VOID(insert_filter, (request_rec *r), (r))
AP_IMPLEMENT_HOOK_RUN_ALL(int, create_request,
                          (request_rec *r), (r), OK, DECLINED)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -71,6 +71,7 @@
     APR_HOOK_LINK(create_request)
     APR_HOOK_LINK(post_perdir_config)
     APR_HOOK_LINK(dirwalk_stat)
+    APR_HOOK_LINK(force_authn)
 )
 
 AP_IMPLEMENT_HOOK_RUN_FIRST(int,translate_name,
@@ -97,6 +98,8 @@
 AP_IMPLEMENT_HOOK_RUN_FIRST(apr_status_t,dirwalk_stat,
                             (apr_finfo_t *finfo, request_rec *r, apr_int32_t wanted),
                             (finfo, r, wanted), AP_DECLINED)
+AP_IMPLEMENT_HOOK_RUN_FIRST(int,force_authn,
+                            (request_rec *r), (r), DECLINED)
 
 static int auth_internal_per_conf = 0;
 static int auth_internal_per_conf_hooks = 0;
@@ -116,6 +119,39 @@
                       status, r->uri);
         return status;
     }
+}
+
+AP_DECLARE(int) ap_some_authn_required(request_rec *r)
+{
+    int access_status;
+
+    switch (ap_satisfies(r)) {
+    case SATISFY_ALL:
+    case SATISFY_NOSPEC:
+        if ((access_status = ap_run_access_checker(r)) != OK) {
+            break;
+        }
+
+        access_status = ap_run_access_checker_ex(r);
+        if (access_status == DECLINED) {
+            return TRUE;
+        }
+
+        break;
+    case SATISFY_ANY:
+        if ((access_status = ap_run_access_checker(r)) == OK) {
+            break;
+        }
+
+        access_status = ap_run_access_checker_ex(r);
+        if (access_status == DECLINED) {
+            return TRUE;
+        }
+
+        break;
+    }
+
+    return FALSE;
 }
 
 /* This is the master logic for processing requests.  Do NOT duplicate
@@ -236,15 +272,8 @@
             }
 
             access_status = ap_run_access_checker_ex(r);
-            if (access_status == OK) {
-                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
-                              "request authorized without authentication by "
-                              "access_checker_ex hook: %s", r->uri);
-            }
-            else if (access_status != DECLINED) {
-                return decl_die(access_status, "check access", r);
-            }
-            else {
+            if (access_status == DECLINED
+                || (access_status == OK && ap_run_force_authn(r) == OK)) {
                 if ((access_status = ap_run_check_user_id(r)) != OK) {
                     return decl_die(access_status, "check user", r);
                 }
@@ -262,6 +291,14 @@
                     return decl_die(access_status, "check authorization", r);
                 }
             }
+            else if (access_status == OK) {
+                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
+                              "request authorized without authentication by "
+                              "access_checker_ex hook: %s", r->uri);
+            }
+            else {
+                return decl_die(access_status, "check access", r);
+            }
             break;
         case SATISFY_ANY:
             if ((access_status = ap_run_access_checker(r)) == OK) {
@@ -273,15 +310,8 @@
             }
 
             access_status = ap_run_access_checker_ex(r);
-            if (access_status == OK) {
-                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
-                              "request authorized without authentication by "
-                              "access_checker_ex hook: %s", r->uri);
-            }
-            else if (access_status != DECLINED) {
-                return decl_die(access_status, "check access", r);
-            }
-            else {
+            if (access_status == DECLINED
+                || (access_status == OK && ap_run_force_authn(r) == OK)) {
                 if ((access_status = ap_run_check_user_id(r)) != OK) {
                     return decl_die(access_status, "check user", r);
                 }
@@ -298,6 +328,14 @@
                 if ((access_status = ap_run_auth_checker(r)) != OK) {
                     return decl_die(access_status, "check authorization", r);
                 }
+            }
+            else if (access_status == OK) {
+                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
+                              "request authorized without authentication by "
+                              "access_checker_ex hook: %s", r->uri);
+            }
+            else {
+                return decl_die(access_status, "check access", r);
             }
             break;
         }
```
