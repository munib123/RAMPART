# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4898_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4898_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 4766-4806 of the vulnerable file.

 *           imp_sth - drivers private statement handle data
 *           param - parameter number, counting starts with 1
 *           value - value being inserted for parameter "param"
 *           sql_type - SQL type of the value
 *           attribs - bind parameter attributes, currently this must be
 *               one of the values SQL_CHAR, ...
 *           inout - TRUE, if parameter is an output variable (currently
 *               this is not supported)
 *           maxlen - ???
 *
 *  Returns: TRUE for success, FALSE otherwise
 *
 **************************************************************************/

int dbd_bind_ph(SV *sth, imp_sth_t *imp_sth, SV *param, SV *value,
		 IV sql_type, SV *attribs, int is_inout, IV maxlen) {
  dTHX;
  int rc;
  int param_num= SvIV(param);
  int idx= param_num - 1;
  char err_msg[64];
  D_imp_xxh(sth);

#if MYSQL_VERSION_ID >= SERVER_PREPARE_VERSION
  STRLEN slen;
  char *buffer= NULL;
  int buffer_is_null= 0;
  int buffer_length= slen;
  unsigned int buffer_type= 0;
  IV tmp;
#endif

  D_imp_dbh_from_sth;
  ASYNC_CHECK_RETURN(sth, FALSE);

  if (DBIc_TRACE_LEVEL(imp_xxh) >= 2)
    PerlIO_printf(DBIc_LOGPIO(imp_xxh),
                  "   Called: dbd_bind_ph\n");

  attribs= attribs;
  maxlen= maxlen;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4783,7 +4783,7 @@
   int rc;
   int param_num= SvIV(param);
   int idx= param_num - 1;
-  char err_msg[64];
+  char *err_msg;
   D_imp_xxh(sth);
 
 #if MYSQL_VERSION_ID >= SERVER_PREPARE_VERSION
@@ -4826,9 +4826,9 @@
   {
     if (! looks_like_number(value))
     {
-      sprintf(err_msg,
+      err_msg = SvPVX(sv_2mortal(newSVpvf(
               "Binding non-numeric field %d, value %s as a numeric!",
-              param_num, neatsvpv(value,0));
+              param_num, neatsvpv(value,0))));
       do_error(sth, JW_ERR_ILLEGAL_PARAM_NUM, err_msg, NULL);
     }
   }
```
