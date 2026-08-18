# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 1571_7
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1571_7`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 403-453 of the vulnerable file.

  if (mysql_real_query(mysql, query.str, query.length-1))
    db_error(mysql); /* We shall countinue here, if --force was given */
}




static MYSQL *db_connect(char *host, char *database,
                         char *user, char *passwd)
{
  MYSQL *mysql;
  if (verbose)
    fprintf(stdout, "Connecting to %s\n", host ? host : "localhost");
  if (!(mysql= mysql_init(NULL)))
    return 0;
  if (opt_compress)
    mysql_options(mysql,MYSQL_OPT_COMPRESS,NullS);
  if (opt_local_file)
    mysql_options(mysql,MYSQL_OPT_LOCAL_INFILE,
		  (char*) &opt_local_file);
#ifdef HAVE_OPENSSL
  if (opt_use_ssl)
  {
    mysql_ssl_set(mysql, opt_ssl_key, opt_ssl_cert, opt_ssl_ca,
		  opt_ssl_capath, opt_ssl_cipher);
    mysql_options(mysql, MYSQL_OPT_SSL_CRL, opt_ssl_crl);
    mysql_options(mysql, MYSQL_OPT_SSL_CRLPATH, opt_ssl_crlpath);
  }
  mysql_options(mysql,MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
                (char*)&opt_ssl_verify_server_cert);
#endif
  if (opt_protocol)
    mysql_options(mysql,MYSQL_OPT_PROTOCOL,(char*)&opt_protocol);
  if (opt_bind_addr)
    mysql_options(mysql,MYSQL_OPT_BIND,opt_bind_addr);
#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  if (shared_memory_base_name)
    mysql_options(mysql,MYSQL_SHARED_MEMORY_BASE_NAME,shared_memory_base_name);
#endif

  if (opt_plugin_dir && *opt_plugin_dir)
    mysql_options(mysql, MYSQL_PLUGIN_DIR, opt_plugin_dir);

  if (opt_default_auth && *opt_default_auth)
    mysql_options(mysql, MYSQL_DEFAULT_AUTH, opt_default_auth);

  mysql_options(mysql, MYSQL_SET_CHARSET_NAME, default_charset);
  mysql_options(mysql, MYSQL_OPT_CONNECT_ATTR_RESET, 0);
  mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD,
                 "program_name", "mysqlimport");
  if (!(mysql_real_connect(mysql,host,user,passwd,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -420,17 +420,7 @@
   if (opt_local_file)
     mysql_options(mysql,MYSQL_OPT_LOCAL_INFILE,
 		  (char*) &opt_local_file);
-#ifdef HAVE_OPENSSL
-  if (opt_use_ssl)
-  {
-    mysql_ssl_set(mysql, opt_ssl_key, opt_ssl_cert, opt_ssl_ca,
-		  opt_ssl_capath, opt_ssl_cipher);
-    mysql_options(mysql, MYSQL_OPT_SSL_CRL, opt_ssl_crl);
-    mysql_options(mysql, MYSQL_OPT_SSL_CRLPATH, opt_ssl_crlpath);
-  }
-  mysql_options(mysql,MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
-                (char*)&opt_ssl_verify_server_cert);
-#endif
+  SSL_SET_OPTIONS(mysql);
   if (opt_protocol)
     mysql_options(mysql,MYSQL_OPT_PROTOCOL,(char*)&opt_protocol);
   if (opt_bind_addr)
```
