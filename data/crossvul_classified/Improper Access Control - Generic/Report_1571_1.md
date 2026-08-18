# CrossVul Fix Pair: Improper Access Control in cpp
**Pair ID:** 1571_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1571_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```cpp
Lines 141-191 of the vulnerable file.

  case OPT_MYSQL_PROTOCOL:
#ifndef EMBEDDED_LIBRARY
    opt_protocol= find_type_or_exit(argument, &sql_protocol_typelib,
				    opt->name);
#endif
    break;
  case 'W':
#ifdef __WIN__
    opt_protocol = MYSQL_PROTOCOL_PIPE;
#endif
    break;
  }
  return 0;
}


/* Initialize options for the given connection handle. */
static void
init_connection_options(MYSQL *mysql)
{
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

#ifdef HAVE_SMEM
  if (shared_memory_base_name)
    mysql_options(mysql, MYSQL_SHARED_MEMORY_BASE_NAME, shared_memory_base_name);
#endif
}


/**
  Reads the response from stdin and returns the first character.

  @param    Optional message do be displayed.

  @return   First character of input string
*/
int get_response(const char *opt_message)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,17 +158,7 @@
 static void
 init_connection_options(MYSQL *mysql)
 {
-#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
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
 
   if (opt_protocol)
     mysql_options(mysql, MYSQL_OPT_PROTOCOL, (char*) &opt_protocol);
```
