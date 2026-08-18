# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in cpp
**Pair ID:** 3092_0
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3092_0`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```cpp
Lines 5663-5703 of the vulnerable file.

      lua_push_str_table_entry(L, "ifname", iface->get_name());
    } else if(!enforce_allowed_interface) {
      goto set_default_if_name_in_session;
    } else {
      // TODO: handle the case where the user has
      // an allowed interface that is not presently available
      // (e.g., not running?)
    }
  }
}

/* ****************************************** */

int Lua::handle_script_request(struct mg_connection *conn,
			       const struct mg_request_info *request_info,
			       char *script_path) {
  char buf[64], key[64], ifname[MAX_INTERFACE_NAME_LEN];
  char *_cookies, user[64] = { '\0' }, outbuf[FILENAME_MAX];
  AddressTree ptree;
  int rc;

  if(!L) return(-1);

  luaL_openlibs(L); /* Load base libraries */
  lua_register_classes(L, true); /* Load custom classes */

  lua_pushlightuserdata(L, (char*)conn);
  lua_setglobal(L, CONST_HTTP_CONN);

  /* Put the GET params into the environment */
  lua_newtable(L);
  if(request_info->query_string != NULL) {
    char *query_string = strdup(request_info->query_string);

    if(query_string) {
      char *where;
      char *tok;

      // ntop->getTrace()->traceEvent(TRACE_WARNING, "[HTTP] %s", query_string);

      tok = strtok_r(query_string, "&", &where);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5680,7 +5680,8 @@
   char *_cookies, user[64] = { '\0' }, outbuf[FILENAME_MAX];
   AddressTree ptree;
   int rc;
-
+  bool csrf_found = false;
+  
   if(!L) return(-1);
 
   luaL_openlibs(L); /* Load base libraries */
@@ -5693,11 +5694,11 @@
   lua_newtable(L);
   if(request_info->query_string != NULL) {
     char *query_string = strdup(request_info->query_string);
-
+    
     if(query_string) {
       char *where;
       char *tok;
-
+      
       // ntop->getTrace()->traceEvent(TRACE_WARNING, "[HTTP] %s", query_string);
 
       tok = strtok_r(query_string, "&", &where);
@@ -5759,6 +5760,8 @@
 				    msg, PAGE_ERROR, query_string, msg));
 		} else
 		  ntop->getRedis()->delKey(decoded_buf);
+
+		csrf_found = true;
 	      }
 
 	      lua_push_str_table_entry(L, tok, decoded_buf);
@@ -5777,6 +5780,13 @@
     } else
       ntop->getTrace()->traceEvent(TRACE_WARNING, "Not enough memory");
   }
+
+  if(strstr(request_info->uri, "/admin/") && (!csrf_found)) {
+    const char *msg = "Missing CSRF parameter";
+    
+    return(send_error(conn, 500 /* Internal server error */, msg, PAGE_ERROR, request_info->uri, msg));
+  }
+  
   lua_setglobal(L, "_GET"); /* Like in php */
 
   /* _SERVER */
```
