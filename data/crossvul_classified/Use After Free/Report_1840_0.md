# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 1840_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1840_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 2068-2111 of the vulnerable file.

  password=	safe_hv_fetch(aTHX_ hv, "password", 8);
  dbname=	safe_hv_fetch(aTHX_ hv, "database", 8);
  mysql_socket=	safe_hv_fetch(aTHX_ hv, "mysql_socket", 12);

  if (DBIc_TRACE_LEVEL(imp_xxh) >= 2)
    PerlIO_printf(DBIc_LOGPIO(imp_xxh),
		  "imp_dbh->my_login : dbname = %s, uid = %s, pwd = %s," \
		  "host = %s, port = %s\n",
		  dbname ? dbname : "NULL",
		  user ? user : "NULL",
		  password ? password : "NULL",
		  host ? host : "NULL",
		  port ? port : "NULL");

  if (!imp_dbh->pmysql) {
     fresh = 1;
     Newz(908, imp_dbh->pmysql, 1, MYSQL);
  }
  result = mysql_dr_connect(dbh, imp_dbh->pmysql, mysql_socket, host, port, user,
			  password, dbname, imp_dbh) ? TRUE : FALSE;
  if (fresh && !result) {
      /* Prevent leaks, but do not free in case of a reconnect. See #97625 */
      Safefree(imp_dbh->pmysql);
  }
  return result;
}


/**************************************************************************
 *
 *  Name:    dbd_db_login
 *
 *  Purpose: Called for connecting to a database and logging in.
 *
 *  Input:   dbh - database handle being initialized
 *           imp_dbh - drivers private database handle data
 *           dbname - the database we want to log into; may be like
 *               "dbname:host" or "dbname:host:port"
 *           user - user name to connect as
 *           password - passwort to connect with
 *
 *  Returns: TRUE for success, FALSE otherwise; do_error has already
 *           been called in the latter case
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2085,10 +2085,6 @@
   }
   result = mysql_dr_connect(dbh, imp_dbh->pmysql, mysql_socket, host, port, user,
 			  password, dbname, imp_dbh) ? TRUE : FALSE;
-  if (fresh && !result) {
-      /* Prevent leaks, but do not free in case of a reconnect. See #97625 */
-      Safefree(imp_dbh->pmysql);
-  }
   return result;
 }
 
@@ -2142,9 +2138,12 @@
 
   if (!my_login(aTHX_ dbh, imp_dbh))
   {
-    if(imp_dbh->pmysql)
+    if(imp_dbh->pmysql) {
         do_error(dbh, mysql_errno(imp_dbh->pmysql),
                 mysql_error(imp_dbh->pmysql) ,mysql_sqlstate(imp_dbh->pmysql));
+        Safefree(imp_dbh->pmysql);
+
+    }
     return FALSE;
   }
 
```
