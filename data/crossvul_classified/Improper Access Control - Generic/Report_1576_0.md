# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1576_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1576_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 465-505 of the vulnerable file.

 * 20140627.2 (2.5.0-dev)  Added is_name_matchable to proxy_worker_shared.
                           Added ap_proxy_define_match_worker().
 * 20140627.3 (2.5.0-dev)  Add ap_copy_scoreboard_worker()
 * 20140627.4 (2.5.0-dev)  Added ap_parse_token_list_strict() to httpd.h.
 * 20140627.5 (2.5.0-dev)  Add r->trailers_{in,out}
 * 20140627.6 (2.5.0-dev)  Added ap_pcre_version_string(), AP_REG_PCRE_COMPILED
 *                         and AP_REG_PCRE_LOADED to ap_regex.h.
 * 20140627.7 (2.5.0-dev)  Add listener bucket in scoreboard.h's process_score.
 * 20140627.8 (2.5.0-dev)  Add ap_set_listencbratio(), ap_close_listeners_ex(),
 *                         ap_duplicate_listeners(), ap_num_listen_buckets and
 *                         ap_have_so_reuseport to ap_listen.h.
 * 20140627.9 (2.5.0-dev)  Add cgi_pass_auth and AP_CGI_PASS_AUTH_* to 
 *                         core_dir_config
 * 20140627.10 (2.5.0-dev) Add ap_proxy_de_socketfy to mod_proxy.h
 * 20150121.0 (2.5.0-dev)  Revert field addition from core_dir_config; r1653666
 * 20150121.1 (2.5.0-dev)  Add cmd_parms_struct.parent to http_config.h
 * 20150121.2 (2.5.0-dev)  Add response_code_exprs to http_core.h
 * 20150222.0 (2.5.0-dev)  ssl pre_handshake hook now indicates proxy|client
 * 20150222.1 (2.5.0-dev)  Add keep_alive_timeout_set to server_rec
 * 20150222.2 (2.5.0-dev)  Add response code 418 as per RFC2324/RFC7168
 */

#define MODULE_MAGIC_COOKIE 0x41503235UL /* "AP25" */

#ifndef MODULE_MAGIC_NUMBER_MAJOR
#define MODULE_MAGIC_NUMBER_MAJOR 20150222
#endif
#define MODULE_MAGIC_NUMBER_MINOR 2                 /* 0...n */

/**
 * Determine if the server's current MODULE_MAGIC_NUMBER is at least a
 * specified value.
 *
 * Useful for testing for features.
 * For example, suppose you wish to use the apr_table_overlap
 *    function.  You can do this:
 *
 * \code
 * #if AP_MODULE_MAGIC_AT_LEAST(19980812,2)
 *     ... use apr_table_overlap()
 * #else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -482,6 +482,8 @@
  * 20150222.0 (2.5.0-dev)  ssl pre_handshake hook now indicates proxy|client
  * 20150222.1 (2.5.0-dev)  Add keep_alive_timeout_set to server_rec
  * 20150222.2 (2.5.0-dev)  Add response code 418 as per RFC2324/RFC7168
+ * 20150222.3 (2.5.0-dev)  Add ap_some_authn_required, ap_force_authn hook.
+ *                         Deprecate broken ap_some_auth_required.
  */
 
 #define MODULE_MAGIC_COOKIE 0x41503235UL /* "AP25" */
@@ -489,7 +491,7 @@
 #ifndef MODULE_MAGIC_NUMBER_MAJOR
 #define MODULE_MAGIC_NUMBER_MAJOR 20150222
 #endif
-#define MODULE_MAGIC_NUMBER_MINOR 2                 /* 0...n */
+#define MODULE_MAGIC_NUMBER_MINOR 3                 /* 0...n */
 
 /**
  * Determine if the server's current MODULE_MAGIC_NUMBER is at least a
```
