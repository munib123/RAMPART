# CrossVul Fix Pair: Improper Certificate Validation in c
**Pair ID:** 4693_0
**Vulnerability Class:** Improper Certificate Validation
**CWE:** CWE-295
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4693_0`)

## Vulnerability Information & PoC

## Description
Improper Certificate Validation - When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client.

## Vulnerable Code
```c
Lines 734-774 of the vulnerable file.

        X509_PURPOSE* ppurpose = X509_PURPOSE_get0(purpose_id);
        if (ppurpose)
        {
          purpose = ppurpose->purpose;
        }
      }
    }
#if 0
    X509_STORE_set_verify_cb_func(store, verify_cb);
#endif
    if (untrustedchain!=NULL)
      sk_X509_pop_free(untrustedchain, X509_free);
    ret = check_cert(store, cert, untrustedchain, purpose);
    lua_pushboolean(L, ret == X509_V_OK);
    lua_pushinteger(L, ret);

    return 2;
  }
}

#if OPENSSL_VERSION_NUMBER > 0x10002000L
/***
check x509 for host (only for openssl 1.0.2 or greater)
@function check_host
@tparam string host hostname to check for match match with x509 subject
@treturn boolean result true if host is present and matches the certificate
*/
static LUA_FUNCTION(openssl_x509_check_host)
{
  X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
  if (lua_isstring(L, 2))
  {
    const char *hostname = lua_tostring(L, 2);
    lua_pushboolean(L, X509_check_host(cert, hostname, strlen(hostname), 0, NULL));
  }
  else
  {
    lua_pushboolean(L, 0);
  }
  return 1;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -751,6 +751,46 @@
   }
 }
 
+/***
+The functions return 1 for a successful match, 0 for a failed match and -1 for
+an internal error: typically a memory allocation failure or an ASN.1 decoding
+error.
+
+All functions can also return -2 if the input is malformed. For example,
+X509_check_host() returns -2 if the provided name contains embedded NULs.
+*/
+static int openssl_push_check_result(lua_State *L, int ret, const char* name)
+{
+  switch (ret)
+  {
+  case 1:
+    lua_pushboolean(L, 1);
+    if (name)
+    {
+      lua_pushstring(L, name);
+      ret = 2;
+    }
+    break;
+  case 0:
+    lua_pushboolean(L, 0);
+    ret = 1;
+    break;
+  case -1:
+    lua_pushnil(L);
+    lua_pushliteral(L, "internal");
+    ret = 2;
+  case -2:
+    lua_pushnil(L);
+    lua_pushliteral(L, "malformed");
+    ret = 2;
+  default:
+    lua_pushnil(L);
+    lua_pushinteger(L, ret);
+    ret = 2;
+  }
+  return ret;
+}
+
 #if OPENSSL_VERSION_NUMBER > 0x10002000L
 /***
 check x509 for host (only for openssl 1.0.2 or greater)
@@ -761,17 +801,17 @@
 static LUA_FUNCTION(openssl_x509_check_host)
 {
   X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
-  if (lua_isstring(L, 2))
-  {
-    const char *hostname = lua_tostring(L, 2);
-    lua_pushboolean(L, X509_check_host(cert, hostname, strlen(hostname), 0, NULL));
-  }
-  else
-  {
-    lua_pushboolean(L, 0);
-  }
-  return 1;
-}
+  size_t sz;
+  const char* hostname = luaL_checklstring(L, 2, &sz);
+  int flags = luaL_optint(L, 3, 0);
+  char *peer = NULL;
+
+  int ret = X509_check_host(cert, hostname, sz, flags, &peer);
+  ret = openssl_push_check_result(L, ret, peer);
+  OPENSSL_free(peer);
+  return ret;
+}
+
 /***
 check x509 for email address (only for openssl 1.0.2 or greater)
 @tparam string email to check for match match with x509 subject
@@ -781,16 +821,11 @@
 static LUA_FUNCTION(openssl_x509_check_email)
 {
   X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
-  if (lua_isstring(L, 2))
-  {
-    const char *email = lua_tostring(L, 2);
-    lua_pushboolean(L, X509_check_email(cert, email, strlen(email), 0));
-  }
-  else
-  {
-    lua_pushboolean(L, 0);
-  }
-  return 1;
+  size_t sz;
+  const char *email = luaL_checklstring(L, 2, &sz);
+  int flags = luaL_optint(L, 3, 0);
+  int ret = X509_check_email(cert, email, sz, flags);
+  return openssl_push_check_result(L, ret, NULL);
 }
 
 /***
@@ -799,19 +834,14 @@
 @tparam string ip to check for match match with x509 subject
 @treturn boolean result true if host is present and matches the certificate
 */
-static LUA_FUNCTION(openssl_x509_check_ip_asc)
+static LUA_FUNCTION(openssl_x509_check_ip)
 {
   X509 * cert = CHECK_OBJECT(1, X509, "openssl.x509");
-  if (lua_isstring(L, 2))
-  {
-    const char *ip_asc = lua_tostring(L, 2);
-    lua_pushboolean(L, X509_check_ip_asc(cert, ip_asc, 0));
-  }
-  else
-  {
-    lua_pushboolean(L, 0);
-  }
-  return 1;
+  size_t sz;
+  const char *ip = luaL_checklstring(L, 2, &sz);
+  int flags = luaL_optint(L, 3, 0);
+  int ret = X509_check_ip(cert, (const unsigned char*)ip, sz, flags);
+  return openssl_push_check_result(L, ret, NULL);
 }
 #endif
 
@@ -1360,7 +1390,7 @@
 #if OPENSSL_VERSION_NUMBER > 0x10002000L
   {"check_host",  openssl_x509_check_host},
   {"check_email", openssl_x509_check_email},
-  {"check_ip_asc", openssl_x509_check_ip_asc},
+  {"check_ip_asc", openssl_x509_check_ip},
 #endif
   {"pubkey",      openssl_x509_public_key},
   {"version",     openssl_x509_version},
@@ -1383,6 +1413,25 @@
 
   {NULL,      NULL},
 };
+
+#if OPENSSL_VERSION_NUMBER > 0x10002000L
+static LuaL_Enumeration check_flags_const[] =
+{
+#define DEFINE_ENUM(x)  \
+  {#x,  X509_CHECK_FLAG_##x}
+  DEFINE_ENUM(ALWAYS_CHECK_SUBJECT),
+#if OPENSSL_VERSION_NUMBER > 0x10100000L
+  DEFINE_ENUM(NEVER_CHECK_SUBJECT),
+#endif
+  DEFINE_ENUM(NO_WILDCARDS),
+  DEFINE_ENUM(NO_PARTIAL_WILDCARDS),
+  DEFINE_ENUM(MULTI_LABEL_WILDCARDS),
+  DEFINE_ENUM(SINGLE_LABEL_SUBDOMAINS),
+#undef DEFINE_ENUM
+
+  {NULL,           0}
+};
+#endif
 
 int luaopen_x509(lua_State *L)
 {
@@ -1411,5 +1460,12 @@
   lua_pushliteral(L, MYVERSION);
   lua_settable(L, -3);
 
+#if OPENSSL_VERSION_NUMBER > 0x10002000L
+  lua_pushliteral(L, "check_flag");
+  lua_newtable(L);
+  auxiliar_enumerate(L, -1, check_flags_const);
+  lua_settable(L, -3);
+#endif
+
   return 1;
 }
```
