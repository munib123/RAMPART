# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5629_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5629_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 279-319 of the vulnerable file.

	    s = "referencing nonexistent obj";
	    break;
	case HAS_OPENACTION:
	    s = "has /OpenAction";
	    break;
	case HAS_LAUNCHACTION:
	    s = "has /LaunchAction";
	    break;
	case BAD_STREAMLEN:
	    s = "bad /Length, too small";
	    break;
	case ENCRYPTED_PDF:
	    s = "PDF is encrypted";
	    break;
	case LINEARIZED_PDF:
	    s = "linearized PDF";
	    break;
	case MANY_FILTERS:
	    s = "more than 2 filters per obj";
	    break;
    }
    cli_dbgmsg("cli_pdf: %s flagged in object %u %u\n", s, obj->id>>8, obj->id&0xff);
}

static int filter_flatedecode(struct pdf_struct *pdf, struct pdf_obj *obj,
			      const char *buf, off_t len, int fout, off_t *sum)
{
    int skipped = 0;
    int zstat;
    z_stream stream;
    off_t nbytes;
    char output[BUFSIZ];

    if (len == 0)
	return CL_CLEAN;

    if (*buf == '\r') {
	buf++;
	len--;
	pdfobj_flag(pdf, obj, BAD_STREAMSTART);
	/* PDF spec says stream is followed by \r\n or \n, but not \r alone.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -296,6 +296,9 @@
 	case MANY_FILTERS:
 	    s = "more than 2 filters per obj";
 	    break;
+	case DECRYPTABLE_PDF:
+	    s = "decryptable PDF";
+	    break;
     }
     cli_dbgmsg("cli_pdf: %s flagged in object %u %u\n", s, obj->id>>8, obj->id&0xff);
 }
@@ -567,6 +570,8 @@
     char *ascii_decoded = NULL;
     int dump = 1;
 
+    cli_dbgmsg("pdf_extract_obj: obj %u %u\n", obj->id>>8, obj->id&0xff);
+
     /* TODO: call bytecode hook here, allow override dumpability */
     if ((!(obj->flags & (1 << OBJ_STREAM)) ||
 	(obj->flags & (1 << OBJ_HASFILTERS)))
@@ -585,7 +590,7 @@
     }
     if (!dump)
 	return CL_CLEAN;
-    cli_dbgmsg("cli_pdf: dumping obj %u %u\n", obj->id>>8, obj->id);
+    cli_dbgmsg("cli_pdf: dumping obj %u %u\n", obj->id>>8, obj->id&0xff);
     snprintf(fullname, sizeof(fullname), "%s"PATHSEP"pdf%02u", pdf->dir, pdf->files++);
     fout = open(fullname,O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
     if (fout < 0) {
@@ -907,6 +912,7 @@
 	q2 = pdf_nextobject(q, bytesleft);
 	bytesleft -= q2 -q;
 	if (!q2 || bytesleft < 0) {
+            cli_dbgmsg("cli_pdf: %u %u obj: no dictionary\n", obj->id>>8, obj->id&0xff);
 	    return;
 	}
 	q3 = memchr(q-1, '<', q2-q+1);
@@ -922,6 +928,7 @@
 	q2 = pdf_nextobject(q, bytesleft);
 	bytesleft -= q2 -q;
 	if (!q2 || bytesleft < 0) {
+            cli_dbgmsg("cli_pdf: %u %u obj: broken dictionary\n", obj->id>>8, obj->id&0xff);
 	    return;
 	}
 	q3 = memchr(q-1, '>', q2-q+1);
@@ -1262,7 +1269,7 @@
 	    password_empty = 1;
 	    /* Algorithm 3.2a could be used to recover encryption key */
 	}
-    } else {
+    } else if ((R >= 2) && (R <= 4)) {
 	/* 7.6.3.3 Algorithm 2 */
 	cli_md5_init(&md5);
 	/* empty password, password == padding */
@@ -1276,9 +1283,9 @@
 	    cli_md5_update(&md5, &v, 4);
 	}
 	cli_md5_final(result, &md5);
+	if (length > 128)
+	    length = 128;
 	if (R >= 3) {
-	    if (length > 128)
-		length = 128;
 	    for (i=0;i<50;i++) {
 		cli_md5_init(&md5);
 		cli_md5_update(&md5, result, length/8);
@@ -1329,6 +1336,11 @@
 	    cli_dbgmsg("cli_pdf: invalid revision %d\n", R);
 	}
     }
+    else {
+	/* Supported R is in {2,3,4,5} */
+	cli_dbgmsg("cli_pdf: R value out of range\n");
+	return;
+    }
     if (password_empty) {
 	cli_dbgmsg("cli_pdf: user password is empty\n");
 	/* The key we computed above is the key used to encrypt the streams.
@@ -1393,6 +1405,10 @@
 	R = pdf_readint(q, len, "/R");
 	if (R == ~0u) {
 	    cli_dbgmsg("cli_pdf: invalid R\n");
+	    break;
+	}
+	if ((R > 5) || (R < 2)) {
+	    cli_dbgmsg("cli_pdf: R value outside supported range [2..5]\n");
 	    break;
 	}
 
```
