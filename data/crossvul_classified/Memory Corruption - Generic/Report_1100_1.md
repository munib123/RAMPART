# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1100_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1100_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-29 of the vulnerable file.

#ifndef NGIFLIB_NO_FILE
#include <stdio.h>
#endif /* NGIFLIB_NO_FILE */

#include "ngiflib.h"

/* decodeur GIF en C portable (pas de pb big/little endian)
 * Thomas BERNARD. janvier 2004.
 * (c) 2004-2017 Thomas Bernard. All rights reserved
 */

/* Fonction de debug */
#ifdef DEBUG
void fprintf_ngiflib_img(FILE * f, struct ngiflib_img * i) {
	fprintf(f, "  * ngiflib_img @ %p\n", i);
	fprintf(f, "    next = %p\n", i->next);
	fprintf(f, "    parent = %p\n", i->parent);
	fprintf(f, "    palette = %p\n", i->palette);
	fprintf(f, "    %3d couleurs", i->ncolors);
	if(i->interlaced) fprintf(f, " interlaced");
	fprintf(f, "\n    taille : %dx%d, pos (%d,%d)\n", i->width, i->height, i->posX, i->posY);
	fprintf(f, "    sort_flag=%x localpalbits=%d\n", i->sort_flag, i->localpalbits);
}
#endif /* DEBUG */

void GifImgDestroy(struct ngiflib_img * i) {
	if(i==NULL) return;
	if(i->next) GifImgDestroy(i->next);
	if(i->palette && (i->palette != i->parent->palette))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,7 +6,7 @@
 
 /* decodeur GIF en C portable (pas de pb big/little endian)
  * Thomas BERNARD. janvier 2004.
- * (c) 2004-2017 Thomas Bernard. All rights reserved
+ * (c) 2004-2019 Thomas Bernard. All rights reserved
  */
 
 /* Fonction de debug */
@@ -135,28 +135,30 @@
 			break;
 		case 1:	/* 1st pass : every eighth row starting from 0 */
 			context->curY += 8;
-			if(context->curY >= p->height) {
-				context->pass++;
-				context->curY = i->posY + 4;
-			}
 			break;
 		case 2:	/* 2nd pass : every eighth row starting from 4 */
 			context->curY += 8;
-			if(context->curY >= p->height) {
-				context->pass++;
-				context->curY = i->posY + 2;
-			}
 			break;
 		case 3:	/* 3rd pass : every fourth row starting from 2 */
 			context->curY += 4;
-			if(context->curY >= p->height) {
-				context->pass++;
-				context->curY = i->posY + 1;
-			}
 			break;
 		case 4:	/* 4th pass : every odd row */
 			context->curY += 2;
 			break;
+		}
+		while(context->pass > 0 && context->pass < 4 &&
+		      context->curY >= p->height) {
+			switch(++context->pass) {
+			case 2:	/* 2nd pass : every eighth row starting from 4 */
+				context->curY = i->posY + 4;
+				break;
+			case 3:	/* 3rd pass : every fourth row starting from 2 */
+				context->curY = i->posY + 2;
+				break;
+			case 4:	/* 4th pass : every odd row */
+				context->curY = i->posY + 1;
+				break;
+			}
 		}
 #ifndef NGIFLIB_INDEXED_ONLY
 		if(p->mode & NGIFLIB_MODE_INDEXED) {
@@ -249,28 +251,30 @@
 				break;
 			case 1:	/* 1st pass : every eighth row starting from 0 */
 				context->curY += 8;
-				if(context->curY >= p->height) {
-					context->pass++;
-					context->curY = i->posY + 4;
-				}
 				break;
 			case 2:	/* 2nd pass : every eighth row starting from 4 */
 				context->curY += 8;
-				if(context->curY >= p->height) {
-					context->pass++;
-					context->curY = i->posY + 2;
-				}
 				break;
 			case 3:	/* 3rd pass : every fourth row starting from 2 */
 				context->curY += 4;
-				if(context->curY >= p->height) {
-					context->pass++;
-					context->curY = i->posY + 1;
-				}
 				break;
 			case 4:	/* 4th pass : every odd row */
 				context->curY += 2;
 				break;
+			}
+			while(context->pass > 0 && context->pass < 4 &&
+			      context->curY >= p->height) {
+				switch(++context->pass) {
+				case 2:	/* 2nd pass : every eighth row starting from 4 */
+					context->curY = i->posY + 4;
+					break;
+				case 3:	/* 3rd pass : every fourth row starting from 2 */
+					context->curY = i->posY + 2;
+					break;
+				case 4:	/* 4th pass : every odd row */
+					context->curY = i->posY + 1;
+					break;
+				}
 			}
 #ifndef NGIFLIB_INDEXED_ONLY
 			if(p->mode & NGIFLIB_MODE_INDEXED) {
```
