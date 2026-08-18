# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5418_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5418_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 65-105 of the vulnerable file.

#include "jasper/jas_types.h"
#include "jasper/jas_malloc.h"
#include "jasper/jas_debug.h"
#include "jasper/jas_icc.h"
#include "jasper/jas_cm.h"
#include "jasper/jas_stream.h"
#include "jasper/jas_string.h"

#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>

#define	jas_iccputuint8(out, val)	jas_iccputuint(out, 1, val)
#define	jas_iccputuint16(out, val)	jas_iccputuint(out, 2, val)
#define	jas_iccputsint32(out, val)	jas_iccputsint(out, 4, val)
#define	jas_iccputuint32(out, val)	jas_iccputuint(out, 4, val)
#define	jas_iccputuint64(out, val)	jas_iccputuint(out, 8, val)

static jas_iccattrval_t *jas_iccattrval_create0(void);

static int jas_iccgetuint(jas_stream_t *in, int n, ulonglong *val);
static int jas_iccgetuint8(jas_stream_t *in, jas_iccuint8_t *val);
static int jas_iccgetuint16(jas_stream_t *in, jas_iccuint16_t *val);
static int jas_iccgetsint32(jas_stream_t *in, jas_iccsint32_t *val);
static int jas_iccgetuint32(jas_stream_t *in, jas_iccuint32_t *val);
static int jas_iccgetuint64(jas_stream_t *in, jas_iccuint64_t *val);
static int jas_iccputuint(jas_stream_t *out, int n, ulonglong val);
static int jas_iccputsint(jas_stream_t *out, int n, longlong val);
static jas_iccprof_t *jas_iccprof_create(void);
static int jas_iccprof_readhdr(jas_stream_t *in, jas_icchdr_t *hdr);
static int jas_iccprof_writehdr(jas_stream_t *out, jas_icchdr_t *hdr);
static int jas_iccprof_gettagtab(jas_stream_t *in, jas_icctagtab_t *tagtab);
static void jas_iccprof_sorttagtab(jas_icctagtab_t *tagtab);
static int jas_iccattrtab_lookup(jas_iccattrtab_t *attrtab, jas_iccuint32_t name);
static jas_iccattrtab_t *jas_iccattrtab_copy(jas_iccattrtab_t *attrtab);
static jas_iccattrvalinfo_t *jas_iccattrvalinfo_lookup(jas_iccsig_t name);
static int jas_iccgettime(jas_stream_t *in, jas_icctime_t *time);
static int jas_iccgetxyz(jas_stream_t *in, jas_iccxyz_t *xyz);
static int jas_icctagtabent_cmp(const void *src, const void *dst);

static void jas_icccurv_destroy(jas_iccattrval_t *attrval);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,14 +82,14 @@
 
 static jas_iccattrval_t *jas_iccattrval_create0(void);
 
-static int jas_iccgetuint(jas_stream_t *in, int n, ulonglong *val);
+static int jas_iccgetuint(jas_stream_t *in, int n, jas_ulonglong *val);
 static int jas_iccgetuint8(jas_stream_t *in, jas_iccuint8_t *val);
 static int jas_iccgetuint16(jas_stream_t *in, jas_iccuint16_t *val);
 static int jas_iccgetsint32(jas_stream_t *in, jas_iccsint32_t *val);
 static int jas_iccgetuint32(jas_stream_t *in, jas_iccuint32_t *val);
 static int jas_iccgetuint64(jas_stream_t *in, jas_iccuint64_t *val);
-static int jas_iccputuint(jas_stream_t *out, int n, ulonglong val);
-static int jas_iccputsint(jas_stream_t *out, int n, longlong val);
+static int jas_iccputuint(jas_stream_t *out, int n, jas_ulonglong val);
+static int jas_iccputsint(jas_stream_t *out, int n, jas_longlong val);
 static jas_iccprof_t *jas_iccprof_create(void);
 static int jas_iccprof_readhdr(jas_stream_t *in, jas_icchdr_t *hdr);
 static int jas_iccprof_writehdr(jas_stream_t *out, jas_icchdr_t *hdr);
@@ -1603,11 +1603,11 @@
 *
 \******************************************************************************/
 
-static int jas_iccgetuint(jas_stream_t *in, int n, ulonglong *val)
+static int jas_iccgetuint(jas_stream_t *in, int n, jas_ulonglong *val)
 {
 	int i;
 	int c;
-	ulonglong v;
+	jas_ulonglong v;
 	v = 0;
 	for (i = n; i > 0; --i) {
 		if ((c = jas_stream_getc(in)) == EOF)
@@ -1629,7 +1629,7 @@
 
 static int jas_iccgetuint16(jas_stream_t *in, jas_iccuint16_t *val)
 {
-	ulonglong tmp;
+	jas_ulonglong tmp;
 	if (jas_iccgetuint(in, 2, &tmp))
 		return -1;
 	*val = tmp;
@@ -1638,17 +1638,17 @@
 
 static int jas_iccgetsint32(jas_stream_t *in, jas_iccsint32_t *val)
 {
-	ulonglong tmp;
+	jas_ulonglong tmp;
 	if (jas_iccgetuint(in, 4, &tmp))
 		return -1;
-	*val = (tmp & 0x80000000) ? (-JAS_CAST(longlong, (((~tmp) &
-	  0x7fffffff) + 1))) : JAS_CAST(longlong, tmp);
+	*val = (tmp & 0x80000000) ? (-JAS_CAST(jas_longlong, (((~tmp) &
+	  0x7fffffff) + 1))) : JAS_CAST(jas_longlong, tmp);
 	return 0;
 }
 
 static int jas_iccgetuint32(jas_stream_t *in, jas_iccuint32_t *val)
 {
-	ulonglong tmp;
+	jas_ulonglong tmp;
 	if (jas_iccgetuint(in, 4, &tmp))
 		return -1;
 	*val = tmp;
@@ -1657,14 +1657,14 @@
 
 static int jas_iccgetuint64(jas_stream_t *in, jas_iccuint64_t *val)
 {
-	ulonglong tmp;
+	jas_ulonglong tmp;
 	if (jas_iccgetuint(in, 8, &tmp))
 		return -1;
 	*val = tmp;
 	return 0;
 }
 
-static int jas_iccputuint(jas_stream_t *out, int n, ulonglong val)
+static int jas_iccputuint(jas_stream_t *out, int n, jas_ulonglong val)
 {
 	int i;
 	int c;
@@ -1676,9 +1676,9 @@
 	return 0;
 }
 
-static int jas_iccputsint(jas_stream_t *out, int n, longlong val)
-{
-	ulonglong tmp;
+static int jas_iccputsint(jas_stream_t *out, int n, jas_longlong val)
+{
+	jas_ulonglong tmp;
 	tmp = (val < 0) ? (abort(), 0) : val;
 	return jas_iccputuint(out, n, tmp);
 }
@@ -1719,7 +1719,7 @@
 }
 
 
-jas_iccprof_t *jas_iccprof_createfrombuf(uchar *buf, int len)
+jas_iccprof_t *jas_iccprof_createfrombuf(jas_uchar *buf, int len)
 {
 	jas_stream_t *in;
 	jas_iccprof_t *prof;
```
