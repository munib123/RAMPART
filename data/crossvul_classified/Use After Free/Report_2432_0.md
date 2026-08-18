# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2432_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2432_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1979-2019 of the vulnerable file.

    if (!len)
      res= NULL;
  }
  return res;
}

/*
 Frontend for mysql_dr_connect
*/
static int my_login(pTHX_ SV* dbh, imp_dbh_t *imp_dbh)
{
  SV* sv;
  HV* hv;
  char* dbname;
  char* host;
  char* port;
  char* user;
  char* password;
  char* mysql_socket;
  int   result;
  D_imp_xxh(dbh);

  /* TODO- resolve this so that it is set only if DBI is 1.607 */
#define TAKE_IMP_DATA_VERSION 1
#if TAKE_IMP_DATA_VERSION
  if (DBIc_has(imp_dbh, DBIcf_IMPSET))
  { /* eg from take_imp_data() */
    if (DBIc_has(imp_dbh, DBIcf_ACTIVE))
    {
      if (DBIc_TRACE_LEVEL(imp_xxh) >= 2)
        PerlIO_printf(DBIc_LOGPIO(imp_xxh), "my_login skip connect\n");
      /* tell our parent we've adopted an active child */
      ++DBIc_ACTIVE_KIDS(DBIc_PARENT_COM(imp_dbh));
      return TRUE;
    }
    if (DBIc_TRACE_LEVEL(imp_xxh) >= 2)
      PerlIO_printf(DBIc_LOGPIO(imp_xxh),
                    "my_login IMPSET but not ACTIVE so connect not skipped\n");
  }
#endif

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1996,6 +1996,7 @@
   char* password;
   char* mysql_socket;
   int   result;
+  int	fresh = 0;
   D_imp_xxh(dbh);
 
   /* TODO- resolve this so that it is set only if DBI is 1.607 */
@@ -2044,12 +2045,18 @@
 		  port ? port : "NULL");
 
   if (!imp_dbh->pmysql) {
+     fresh = 1;
      Newz(908, imp_dbh->pmysql, 1, MYSQL);
   }
   result = mysql_dr_connect(dbh, imp_dbh->pmysql, mysql_socket, host, port, user,
 			  password, dbname, imp_dbh) ? TRUE : FALSE;
-  if (!result)
+  if (fresh && !result) {
+      /* Prevent leaks, but do not free in case of a reconnect. See #97625 */
+      do_error(dbh, mysql_errno(imp_dbh->pmysql),
+              mysql_error(imp_dbh->pmysql) ,mysql_sqlstate(imp_dbh->pmysql));
       Safefree(imp_dbh->pmysql);
+      imp_dbh->pmysql = NULL;
+  }
   return result;
 }
 
@@ -2102,8 +2109,9 @@
 
   if (!my_login(aTHX_ dbh, imp_dbh))
   {
-    do_error(dbh, mysql_errno(imp_dbh->pmysql),
-            mysql_error(imp_dbh->pmysql) ,mysql_sqlstate(imp_dbh->pmysql));
+    if(imp_dbh->pmysql)
+        do_error(dbh, mysql_errno(imp_dbh->pmysql),
+                mysql_error(imp_dbh->pmysql) ,mysql_sqlstate(imp_dbh->pmysql));
     return FALSE;
   }
 
```
