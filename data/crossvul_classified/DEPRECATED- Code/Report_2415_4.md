# CrossVul Fix Pair: DEPRECATED: Code in c
**Pair ID:** 2415_4
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2415_4`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```c
Lines 11-51 of the vulnerable file.

 *	UTF-8 is explained in the IETF RFC XXXX.
 *		ftp://ftp.internic.net/rfc/rfcxxxx.txt
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 */

#include "udfdecl.h"

#include <linux/kernel.h>
#include <linux/string.h>	/* for memset */
#include <linux/nls.h>
#include <linux/crc-itu-t.h>
#include <linux/slab.h>

#include "udf_sb.h"

static int udf_translate_to_linux(uint8_t *, uint8_t *, int, uint8_t *, int);

static int udf_char_to_ustr(struct ustr *dest, const uint8_t *src, int strlen)
{
	if ((!dest) || (!src) || (!strlen) || (strlen > UDF_NAME_LEN - 2))
		return 0;

	memset(dest, 0, sizeof(struct ustr));
	memcpy(dest->u_name, src, strlen);
	dest->u_cmpID = 0x08;
	dest->u_len = strlen;

	return strlen;
}

/*
 * udf_build_ustr
 */
int udf_build_ustr(struct ustr *dest, dstring *ptr, int size)
{
	int usesize;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,7 +28,8 @@
 
 #include "udf_sb.h"
 
-static int udf_translate_to_linux(uint8_t *, uint8_t *, int, uint8_t *, int);
+static int udf_translate_to_linux(uint8_t *, int, uint8_t *, int, uint8_t *,
+				  int);
 
 static int udf_char_to_ustr(struct ustr *dest, const uint8_t *src, int strlen)
 {
@@ -333,8 +334,8 @@
 	return u_len + 1;
 }
 
-int udf_get_filename(struct super_block *sb, uint8_t *sname, uint8_t *dname,
-		     int flen)
+int udf_get_filename(struct super_block *sb, uint8_t *sname, int slen,
+		     uint8_t *dname, int dlen)
 {
 	struct ustr *filename, *unifilename;
 	int len = 0;
@@ -347,7 +348,7 @@
 	if (!unifilename)
 		goto out1;
 
-	if (udf_build_ustr_exact(unifilename, sname, flen))
+	if (udf_build_ustr_exact(unifilename, sname, slen))
 		goto out2;
 
 	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UTF8)) {
@@ -366,7 +367,8 @@
 	} else
 		goto out2;
 
-	len = udf_translate_to_linux(dname, filename->u_name, filename->u_len,
+	len = udf_translate_to_linux(dname, dlen,
+				     filename->u_name, filename->u_len,
 				     unifilename->u_name, unifilename->u_len);
 out2:
 	kfree(unifilename);
@@ -403,10 +405,12 @@
 #define EXT_MARK		'.'
 #define CRC_MARK		'#'
 #define EXT_SIZE 		5
-
-static int udf_translate_to_linux(uint8_t *newName, uint8_t *udfName,
-				  int udfLen, uint8_t *fidName,
-				  int fidNameLen)
+/* Number of chars we need to store generated CRC to make filename unique */
+#define CRC_LEN			5
+
+static int udf_translate_to_linux(uint8_t *newName, int newLen,
+				  uint8_t *udfName, int udfLen,
+				  uint8_t *fidName, int fidNameLen)
 {
 	int index, newIndex = 0, needsCRC = 0;
 	int extIndex = 0, newExtIndex = 0, hasExt = 0;
@@ -439,7 +443,7 @@
 					newExtIndex = newIndex;
 				}
 			}
-			if (newIndex < 256)
+			if (newIndex < newLen)
 				newName[newIndex++] = curr;
 			else
 				needsCRC = 1;
@@ -467,13 +471,13 @@
 				}
 				ext[localExtIndex++] = curr;
 			}
-			maxFilenameLen = 250 - localExtIndex;
+			maxFilenameLen = newLen - CRC_LEN - localExtIndex;
 			if (newIndex > maxFilenameLen)
 				newIndex = maxFilenameLen;
 			else
 				newIndex = newExtIndex;
-		} else if (newIndex > 250)
-			newIndex = 250;
+		} else if (newIndex > newLen - CRC_LEN)
+			newIndex = newLen - CRC_LEN;
 		newName[newIndex++] = CRC_MARK;
 		valueCRC = crc_itu_t(0, fidName, fidNameLen);
 		newName[newIndex++] = hex_asc_upper_hi(valueCRC >> 8);
```
