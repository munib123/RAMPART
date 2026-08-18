# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2118_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2118_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 92-134 of the vulnerable file.

   driver_free((char *)handle);
}


#define DEFLATE 1
#define INFLATE 2

#define die_unless(cond, errstr)				\
	 if (!(cond))						\
	 {							\
	    rlen = strlen(errstr) + 1;				\
	    b = driver_realloc_binary(b, rlen);			\
	    b->orig_bytes[0] = 1;				\
	    strncpy(b->orig_bytes + 1, errstr, rlen - 1);	\
	    *rbuf = (char *)b;					\
	    return rlen;					\
	 }


static ErlDrvSSizeT ejabberd_zlib_drv_control(ErlDrvData handle,
				     unsigned int command,
				     char *buf, ErlDrvSizeT len,
				     char **rbuf, ErlDrvSizeT rlen)
{
   ejabberd_zlib_data *d = (ejabberd_zlib_data *)handle;
   int err;
   int size;
   ErlDrvBinary *b;

   switch (command)
   {
      case DEFLATE:
	 size = BUF_SIZE + 1;
	 rlen = 1;
	 b = driver_alloc_binary(size);
	 b->orig_bytes[0] = 0;

	 d->d_stream->next_in = (unsigned char *)buf;
	 d->d_stream->avail_in = len;
	 d->d_stream->avail_out = 0;
	 err = Z_OK;

	 while (err == Z_OK && d->d_stream->avail_out == 0)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,79 +109,86 @@
 
 
 static ErlDrvSSizeT ejabberd_zlib_drv_control(ErlDrvData handle,
-				     unsigned int command,
-				     char *buf, ErlDrvSizeT len,
-				     char **rbuf, ErlDrvSizeT rlen)
-{
-   ejabberd_zlib_data *d = (ejabberd_zlib_data *)handle;
-   int err;
-   int size;
-   ErlDrvBinary *b;
-
-   switch (command)
-   {
-      case DEFLATE:
-	 size = BUF_SIZE + 1;
-	 rlen = 1;
-	 b = driver_alloc_binary(size);
-	 b->orig_bytes[0] = 0;
-
-	 d->d_stream->next_in = (unsigned char *)buf;
-	 d->d_stream->avail_in = len;
-	 d->d_stream->avail_out = 0;
-	 err = Z_OK;
-
-	 while (err == Z_OK && d->d_stream->avail_out == 0)
-	 {
-	    d->d_stream->next_out = (unsigned char *)b->orig_bytes + rlen;
-	    d->d_stream->avail_out = BUF_SIZE;
-
-	    err = deflate(d->d_stream, Z_SYNC_FLUSH);
-	    die_unless((err == Z_OK) || (err == Z_STREAM_END),
-		       "Deflate error");
-
-	    rlen += (BUF_SIZE - d->d_stream->avail_out);
-	    size += (BUF_SIZE - d->d_stream->avail_out);
-	    b = driver_realloc_binary(b, size);
-	 }
-	 b = driver_realloc_binary(b, rlen);
-	 *rbuf = (char *)b;
-	 return rlen;
-      case INFLATE:
-	 size = BUF_SIZE + 1;
-	 rlen = 1;
-	 b = driver_alloc_binary(size);
-	 b->orig_bytes[0] = 0;
-
-	 if (len > 0) {
-	    d->i_stream->next_in = (unsigned char *)buf;
-	    d->i_stream->avail_in = len;
-	    d->i_stream->avail_out = 0;
-	    err = Z_OK;
-
-	    while (err == Z_OK && d->i_stream->avail_out == 0)
-	    {
-	       d->i_stream->next_out = (unsigned char *)b->orig_bytes + rlen;
-	       d->i_stream->avail_out = BUF_SIZE;
-
-	       err = inflate(d->i_stream, Z_SYNC_FLUSH);
-	       die_unless((err == Z_OK) || (err == Z_STREAM_END),
-			  "Inflate error");
-
-	       rlen += (BUF_SIZE - d->i_stream->avail_out);
-	       size += (BUF_SIZE - d->i_stream->avail_out);
-	       b = driver_realloc_binary(b, size);
-	    }
-	 }
-	 b = driver_realloc_binary(b, rlen);
-	 *rbuf = (char *)b;
-	 return rlen;
-   }
-
-   b = driver_alloc_binary(1);
-   b->orig_bytes[0] = 0;
-   *rbuf = (char *)b;
-   return 1;
+        unsigned int command,
+        char *buf, ErlDrvSizeT len,
+        char **rbuf, ErlDrvSizeT rlen)
+{
+    ejabberd_zlib_data *d = (ejabberd_zlib_data *)handle;
+    int err;
+    int size;
+    int size_limit;
+    ErlDrvBinary *b;
+
+    // operation is in command's 2 lower bits and size_limit is in bits higher than 1
+    size_limit = command >> 2; // applies only to inflation
+    command = command & 3;
+    switch (command)
+    {
+        case DEFLATE:
+            size = BUF_SIZE + 1;
+            rlen = 1;
+            b = driver_alloc_binary(size);
+            b->orig_bytes[0] = 0;
+
+            d->d_stream->next_in = (unsigned char *)buf;
+            d->d_stream->avail_in = len;
+            d->d_stream->avail_out = 0;
+            err = Z_OK;
+
+            while (err == Z_OK && d->d_stream->avail_out == 0)
+            {
+                d->d_stream->next_out = (unsigned char *)b->orig_bytes + rlen;
+                d->d_stream->avail_out = BUF_SIZE;
+
+                err = deflate(d->d_stream, Z_SYNC_FLUSH);
+                die_unless((err == Z_OK) || (err == Z_STREAM_END),
+                        "deflate_error");
+
+                rlen += (BUF_SIZE - d->d_stream->avail_out);
+                size += (BUF_SIZE - d->d_stream->avail_out);
+                b = driver_realloc_binary(b, size);
+            }
+            b = driver_realloc_binary(b, rlen);
+            *rbuf = (char *)b;
+            return rlen;
+        case INFLATE:
+            size = BUF_SIZE + 1;
+            rlen = 1;
+            b = driver_alloc_binary(size);
+            b->orig_bytes[0] = 0;
+
+            if (len > 0) {
+                d->i_stream->next_in = (unsigned char *)buf;
+                d->i_stream->avail_in = len;
+                d->i_stream->avail_out = 0;
+                err = Z_OK;
+
+                while (err == Z_OK && d->i_stream->avail_out == 0)
+                {
+                    d->i_stream->next_out = (unsigned char *)b->orig_bytes + rlen;
+                    d->i_stream->avail_out = BUF_SIZE;
+
+                    err = inflate(d->i_stream, Z_SYNC_FLUSH);
+                    die_unless((err == Z_OK) || (err == Z_STREAM_END),
+                            "inflate_error");
+
+                    rlen += (BUF_SIZE - d->i_stream->avail_out);
+                    die_unless((rlen < size_limit) || (size_limit == 0),
+                            "inflate_size_exceeded");
+
+                    size += (BUF_SIZE - d->i_stream->avail_out);
+                    b = driver_realloc_binary(b, size);
+                }
+            }
+            b = driver_realloc_binary(b, rlen);
+            *rbuf = (char *)b;
+            return rlen;
+    }
+
+    b = driver_alloc_binary(1);
+    b->orig_bytes[0] = 0;
+    *rbuf = (char *)b;
+    return 1;
 }
 
 
```
