# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 4902_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4902_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 4033-4073 of the vulnerable file.

       * This is not the way to determine length (this would break blobs!)
       */
      if (fbh->is_null)
        (void) SvOK_off(sv);  /*  Field is NULL, return undef  */
      else
      {
        /* In case of BLOB/TEXT fields we allocate only 8192 bytes
           in dbd_describe() for data. Here we know real size of field
           so we should increase buffer size and refetch column value
        */
        if (fbh->length > buffer->buffer_length || fbh->error)
        {
          if (DBIc_TRACE_LEVEL(imp_xxh) >= 2)
            PerlIO_printf(DBIc_LOGPIO(imp_xxh),
              "\t\tRefetch BLOB/TEXT column: %d, length: %lu, error: %d\n",
              i, fbh->length, fbh->error);

          Renew(fbh->data, fbh->length, char);
          buffer->buffer_length= fbh->length;
          buffer->buffer= (char *) fbh->data;

          if (DBIc_TRACE_LEVEL(imp_xxh) >= 2) {
            int j;
            int m = MIN(*buffer->length, buffer->buffer_length);
            char *ptr = (char*)buffer->buffer;
            PerlIO_printf(DBIc_LOGPIO(imp_xxh),"\t\tbefore buffer->buffer: ");
            for (j = 0; j < m; j++) {
              PerlIO_printf(DBIc_LOGPIO(imp_xxh), "%c", *ptr++);
            }
            PerlIO_printf(DBIc_LOGPIO(imp_xxh),"\n");
          }

          /*TODO: Use offset instead of 0 to fetch only remain part of data*/
          if (mysql_stmt_fetch_column(imp_sth->stmt, buffer , i, 0))
            do_error(sth, mysql_stmt_errno(imp_sth->stmt),
                     mysql_stmt_error(imp_sth->stmt),
                     mysql_stmt_sqlstate(imp_sth->stmt));

          if (DBIc_TRACE_LEVEL(imp_xxh) >= 2) {
            int j;
            int m = MIN(*buffer->length, buffer->buffer_length);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4050,6 +4050,8 @@
           Renew(fbh->data, fbh->length, char);
           buffer->buffer_length= fbh->length;
           buffer->buffer= (char *) fbh->data;
+          imp_sth->stmt->bind[i].buffer_length = fbh->length;
+          imp_sth->stmt->bind[i].buffer = (char *)fbh->data;
 
           if (DBIc_TRACE_LEVEL(imp_xxh) >= 2) {
             int j;
```
