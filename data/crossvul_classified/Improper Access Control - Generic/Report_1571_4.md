# CrossVul Fix Pair: Improper Access Control in cpp
**Pair ID:** 1571_4
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1571_4`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```cpp
Lines 1868-1918 of the vulnerable file.

}


/**
  Create and initialize the global mysql object, and connect to the
  server.

  @retval ERROR_STOP An error occurred - the program should terminate.
  @retval OK_CONTINUE No error, the program should continue.
*/
static Exit_status safe_connect()
{
  mysql= mysql_init(NULL);

  if (!mysql)
  {
    error("Failed on mysql_init.");
    return ERROR_STOP;
  }

#ifdef HAVE_OPENSSL
  if (opt_use_ssl)
  {
    mysql_ssl_set(mysql, opt_ssl_key, opt_ssl_cert, opt_ssl_ca,
                  opt_ssl_capath, opt_ssl_cipher);
    mysql_options(mysql, MYSQL_OPT_SSL_CRL, opt_ssl_crl);
    mysql_options(mysql, MYSQL_OPT_SSL_CRLPATH, opt_ssl_crlpath);
  }
  mysql_options(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
                (char*) &opt_ssl_verify_server_cert);
#endif

  if (opt_plugin_dir && *opt_plugin_dir)
    mysql_options(mysql, MYSQL_PLUGIN_DIR, opt_plugin_dir);

  if (opt_default_auth && *opt_default_auth)
    mysql_options(mysql, MYSQL_DEFAULT_AUTH, opt_default_auth);

  if (opt_protocol)
    mysql_options(mysql, MYSQL_OPT_PROTOCOL, (char*) &opt_protocol);
  if (opt_bind_addr)
    mysql_options(mysql, MYSQL_OPT_BIND, opt_bind_addr);
#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  if (shared_memory_base_name)
    mysql_options(mysql, MYSQL_SHARED_MEMORY_BASE_NAME,
                  shared_memory_base_name);
#endif
  mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_RESET, 0);
  mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD,
                 "program_name", "mysqlbinlog");
  if (!mysql_real_connect(mysql, host, user, pass, 0, port, sock, 0))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1885,17 +1885,7 @@
     return ERROR_STOP;
   }
 
-#ifdef HAVE_OPENSSL
-  if (opt_use_ssl)
-  {
-    mysql_ssl_set(mysql, opt_ssl_key, opt_ssl_cert, opt_ssl_ca,
-                  opt_ssl_capath, opt_ssl_cipher);
-    mysql_options(mysql, MYSQL_OPT_SSL_CRL, opt_ssl_crl);
-    mysql_options(mysql, MYSQL_OPT_SSL_CRLPATH, opt_ssl_crlpath);
-  }
-  mysql_options(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
-                (char*) &opt_ssl_verify_server_cert);
-#endif
+  SSL_SET_OPTIONS(mysql);
 
   if (opt_plugin_dir && *opt_plugin_dir)
     mysql_options(mysql, MYSQL_PLUGIN_DIR, opt_plugin_dir);
```
