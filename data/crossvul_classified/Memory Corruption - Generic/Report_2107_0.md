# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2107_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2107_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 15-55 of the vulnerable file.

 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * softmagic - interpret variable magic from MAGIC
 */

#include "file.h"

#ifndef	lint
FILE_RCSID("@(#)$File: softmagic.c,v 1.170 2014/01/06 02:25:32 christos Exp $")
#endif	/* lint */

#include "magic.h"
#ifdef HAVE_FMTCHECK
#include <stdio.h>
#define F(a, b) fmtcheck((a), (b))
#else
#define F(a, b) (a)
#endif
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#if defined(HAVE_LOCALE_H)
#include <locale.h>
#endif


private int match(struct magic_set *, struct magic *, uint32_t,
    const unsigned char *, size_t, size_t, int, int, int, int, int *, int *,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,7 +32,7 @@
 #include "file.h"
 
 #ifndef	lint
-FILE_RCSID("@(#)$File: softmagic.c,v 1.170 2014/01/06 02:25:32 christos Exp $")
+FILE_RCSID("@(#)$File: softmagic.c,v 1.171 2014/01/08 22:02:06 christos Exp $")
 #endif	/* lint */
 
 #include "magic.h"
@@ -71,6 +71,7 @@
 private void cvt_32(union VALUETYPE *, const struct magic *);
 private void cvt_64(union VALUETYPE *, const struct magic *);
 
+#define OFFSET_OOB(n, o, i)	((n) < (o) || (i) >= ((n) - (o)))
 /*
  * softmagic - lookup one file in parsed, in-memory copy of database
  * Passed the name and FILE * of one file to be typed.
@@ -1223,7 +1224,7 @@
 		}
 		switch (in_type = cvt_flip(m->in_type, flip)) {
 		case FILE_BYTE:
-			if (nbytes < offset || nbytes < (offset + 1))
+			if (OFFSET_OOB(nbytes, offset, 1))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1258,7 +1259,7 @@
 				offset = ~offset;
 			break;
 		case FILE_BESHORT:
-			if (nbytes < offset || nbytes < (offset + 2))
+			if (OFFSET_OOB(nbytes, offset, 2))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1310,7 +1311,7 @@
 				offset = ~offset;
 			break;
 		case FILE_LESHORT:
-			if (nbytes < offset || nbytes < (offset + 2))
+			if (OFFSET_OOB(nbytes, offset, 2))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1362,7 +1363,7 @@
 				offset = ~offset;
 			break;
 		case FILE_SHORT:
-			if (nbytes < offset || nbytes < (offset + 2))
+			if (OFFSET_OOB(nbytes, offset, 2))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1399,7 +1400,7 @@
 			break;
 		case FILE_BELONG:
 		case FILE_BEID3:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1470,7 +1471,7 @@
 			break;
 		case FILE_LELONG:
 		case FILE_LEID3:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1540,7 +1541,7 @@
 				offset = ~offset;
 			break;
 		case FILE_MELONG:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1610,7 +1611,7 @@
 				offset = ~offset;
 			break;
 		case FILE_LONG:
-			if (nbytes < offset || nbytes < (offset + 4))
+			if (OFFSET_OOB(nbytes, offset, 4))
 				return 0;
 			if (off) {
 				switch (m->in_op & FILE_OPS_MASK) {
@@ -1687,14 +1688,14 @@
 	/* Verify we have enough data to match magic type */
 	switch (m->type) {
 	case FILE_BYTE:
-		if (nbytes < (offset + 1)) /* should alway be true */
+		if (OFFSET_OOB(nbytes, offset, 1))
 			return 0;
 		break;
 
 	case FILE_SHORT:
 	case FILE_BESHORT:
 	case FILE_LESHORT:
-		if (nbytes < (offset + 2))
+		if (OFFSET_OOB(nbytes, offset, 2))
 			return 0;
 		break;
 
@@ -1713,31 +1714,31 @@
 	case FILE_FLOAT:
 	case FILE_BEFLOAT:
 	case FILE_LEFLOAT:
-		if (nbytes < (offset + 4))
+		if (OFFSET_OOB(nbytes, offset, 4))
 			return 0;
 		break;
 
 	case FILE_DOUBLE:
 	case FILE_BEDOUBLE:
 	case FILE_LEDOUBLE:
-		if (nbytes < (offset + 8))
+		if (OFFSET_OOB(nbytes, offset, 8))
 			return 0;
 		break;
 
 	case FILE_STRING:
 	case FILE_PSTRING:
 	case FILE_SEARCH:
-		if (nbytes < (offset + m->vallen))
+		if (OFFSET_OOB(nbytes, offset, m->vallen))
 			return 0;
 		break;
 
 	case FILE_REGEX:
-		if (nbytes < offset)
+		if (OFFSET_OOB(nbytes, offset, 0))
 			return 0;
 		break;
 
 	case FILE_INDIRECT:
-		if (nbytes < offset)
+		if (OFFSET_OOB(nbytes, offset, 0))
 			return 0;
 		sbuf = ms->o.buf;
 		soffset = ms->offset;
@@ -1761,7 +1762,7 @@
 		return rv;
 
 	case FILE_USE:
-		if (nbytes < offset)
+		if (OFFSET_OOB(nbytes, offset, 0))
 			return 0;
 		sbuf = m->value.s;
 		if (*sbuf == '^') {
```
