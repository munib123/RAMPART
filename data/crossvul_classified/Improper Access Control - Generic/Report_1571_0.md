# CrossVul Fix Pair: Improper Access Control in cpp
**Pair ID:** 1571_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1571_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```cpp
Lines 4936-4986 of the vulnerable file.

    mysql_options(mysql, MYSQL_INIT_COMMAND, opt_init_command);

  if (opt_connect_timeout)
  {
    uint timeout= opt_connect_timeout;
    mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char*) &timeout);
  }

  if (opt_bind_addr)
    mysql_options(mysql, MYSQL_OPT_BIND, opt_bind_addr);

  if (opt_compress)
    mysql_options(mysql, MYSQL_OPT_COMPRESS, NullS);

  if (!opt_secure_auth)
    mysql_options(mysql, MYSQL_SECURE_AUTH, (char *) &opt_secure_auth);

  if (using_opt_local_infile)
    mysql_options(mysql, MYSQL_OPT_LOCAL_INFILE, (char*) &opt_local_infile);

#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
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

  if (opt_protocol)
    mysql_options(mysql, MYSQL_OPT_PROTOCOL, (char*) &opt_protocol);

#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  if (shared_memory_base_name)
    mysql_options(mysql, MYSQL_SHARED_MEMORY_BASE_NAME, shared_memory_base_name);
#endif

  if (safe_updates)
  {
    char init_command[100];
    sprintf(init_command,
	    "SET SQL_SAFE_UPDATES=1,SQL_SELECT_LIMIT=%lu,MAX_JOIN_SIZE=%lu",
	    select_limit, max_join_size);
    mysql_options(mysql, MYSQL_INIT_COMMAND, init_command);
  }

  mysql_set_character_set(mysql, default_charset);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4953,17 +4953,7 @@
   if (using_opt_local_infile)
     mysql_options(mysql, MYSQL_OPT_LOCAL_INFILE, (char*) &opt_local_infile);
 
-#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
-  if (opt_use_ssl)
-  {
-    mysql_ssl_set(mysql, opt_ssl_key, opt_ssl_cert, opt_ssl_ca,
-		  opt_ssl_capath, opt_ssl_cipher);
-    mysql_options(mysql, MYSQL_OPT_SSL_CRL, opt_ssl_crl);
-    mysql_options(mysql, MYSQL_OPT_SSL_CRLPATH, opt_ssl_crlpath);
-  }
-  mysql_options(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
-                (char*) &opt_ssl_verify_server_cert);
-#endif
+  SSL_SET_OPTIONS(mysql);
 
   if (opt_protocol)
     mysql_options(mysql, MYSQL_OPT_PROTOCOL, (char*) &opt_protocol);
```
