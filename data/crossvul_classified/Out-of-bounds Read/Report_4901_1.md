# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4901_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4901_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2733-2773 of the vulnerable file.

 *           be called in the latter case
 *
 **************************************************************************/
int
dbd_st_prepare(
  SV *sth,
  imp_sth_t *imp_sth,
  char *statement,
  SV *attribs)
{
  int i;
  SV **svp;
  dTHX;
#if MYSQL_VERSION_ID >= SERVER_PREPARE_VERSION
#if MYSQL_VERSION_ID < CALL_PLACEHOLDER_VERSION
  char *str_ptr, *str_last_ptr;
#if MYSQL_VERSION_ID < LIMIT_PLACEHOLDER_VERSION
  int limit_flag=0;
#endif
#endif
  int col_type, prepare_retval;
  MYSQL_BIND *bind, *bind_end;
  imp_sth_phb_t *fbind;
#endif
  D_imp_xxh(sth);
  D_imp_dbh_from_sth;

  if (DBIc_TRACE_LEVEL(imp_xxh) >= 2)
    PerlIO_printf(DBIc_LOGPIO(imp_xxh),
                 "\t-> dbd_st_prepare MYSQL_VERSION_ID %d, SQL statement: %s\n",
                  MYSQL_VERSION_ID, statement);

#if MYSQL_VERSION_ID >= SERVER_PREPARE_VERSION
 /* Set default value of 'mysql_server_prepare' attribute for sth from dbh */
  imp_sth->use_server_side_prepare= imp_dbh->use_server_side_prepare;
  if (attribs)
  {
    svp= DBD_ATTRIB_GET_SVP(attribs, "mysql_server_prepare", 20);
    imp_sth->use_server_side_prepare = (svp) ?
      SvTRUE(*svp) : imp_dbh->use_server_side_prepare;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2750,7 +2750,7 @@
   int limit_flag=0;
 #endif
 #endif
-  int col_type, prepare_retval;
+  int prepare_retval;
   MYSQL_BIND *bind, *bind_end;
   imp_sth_phb_t *fbind;
 #endif
@@ -2946,7 +2946,6 @@
 
       if (DBIc_NUM_PARAMS(imp_sth) > 0)
       {
-        int has_statement_fields= imp_sth->stmt->fields != 0;
         /* Allocate memory for bind variables */
         imp_sth->bind=            alloc_bind(DBIc_NUM_PARAMS(imp_sth));
         imp_sth->fbind=           alloc_fbind(DBIc_NUM_PARAMS(imp_sth));
@@ -2960,20 +2959,7 @@
              bind < bind_end ;
              bind++, fbind++, i++ )
         {
-          /*
-            if this statement has a result set, field types will be
-            correctly identified. If there is no result set, such as
-            with an INSERT, fields will not be defined, and all buffer_type
-            will default to MYSQL_TYPE_VAR_STRING
-          */
-          col_type= (has_statement_fields ?
-                     imp_sth->stmt->fields[i].type : MYSQL_TYPE_STRING);
-
-          bind->buffer_type=  mysql_to_perl_type(col_type);
-
-          if (DBIc_TRACE_LEVEL(imp_xxh) >= 2)
-            PerlIO_printf(DBIc_LOGPIO(imp_xxh), "\t\tmysql_to_perl_type returned %d\n", col_type);
-
+          bind->buffer_type=  MYSQL_TYPE_STRING;
           bind->buffer=       NULL;
           bind->length=       &(fbind->length);
           bind->is_null=      (char*) &(fbind->is_null);
```
