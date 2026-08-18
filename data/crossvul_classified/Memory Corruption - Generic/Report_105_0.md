# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 105_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `105_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 391-431 of the vulnerable file.

	u8 * stack_top;
	u16 clr;
	u16 eof;
	u16 free;
	u16 act_code = 0;
	u16 old_code = 0;
	u16 read_byt;
	u16 ab_prfx[4096];
	u8 ab_suffx[4096];
	u8 ab_stack[4096];
	u8 flags;
	u8 casspecial = 0;

	if(!i) return -1;

	i->posX = GetWord(i->parent);	/* offsetX */
	i->posY = GetWord(i->parent);	/* offsetY */
	i->width = GetWord(i->parent);	/* SizeX   */
	i->height = GetWord(i->parent);	/* SizeY   */

	context.Xtogo = i->width;
	context.curY = i->posY;
#ifdef NGIFLIB_INDEXED_ONLY
	#ifdef NGIFLIB_ENABLE_CALLBACKS
	context.line_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width;
	context.frbuff_p.p8 = context.line_p.p8 + i->posX;
	#else
	context.frbuff_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width + i->posX;
	#endif /* NGIFLIB_ENABLE_CALLBACKS */
#else
	if(i->parent->mode & NGIFLIB_MODE_INDEXED) {
		#ifdef NGIFLIB_ENABLE_CALLBACKS
		context.line_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width;
		context.frbuff_p.p8 = context.line_p.p8 + i->posX;
		#else
		context.frbuff_p.p8 = i->parent->frbuff.p8 + (u32)i->posY*i->parent->width + i->posX;
		#endif /* NGIFLIB_ENABLE_CALLBACKS */
	} else {
		#ifdef NGIFLIB_ENABLE_CALLBACKS
		context.line_p.p32 = i->parent->frbuff.p32 + (u32)i->posY*i->parent->width;
		context.frbuff_p.p32 = context.line_p.p32 + i->posX;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -408,6 +408,24 @@
 	i->width = GetWord(i->parent);	/* SizeX   */
 	i->height = GetWord(i->parent);	/* SizeY   */
 
+	if((i->width > i->parent->width) || (i->height > i->parent->height)) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** ERROR *** Image bigger than global GIF canvas !\n");
+#endif
+		return -1;
+	}
+	if((i->posX + i->width) > i->parent->width) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting X position\n");
+#endif
+		i->posX = i->parent->width - i->width;
+	}
+	if((i->posY + i->height) > i->parent->height) {
+#if !defined(NGIFLIB_NO_FILE)
+		if(i->parent->log) fprintf(i->parent->log, "*** WARNING *** Adjusting Y position\n");
+#endif
+		i->posY = i->parent->height - i->height;
+	}
 	context.Xtogo = i->width;
 	context.curY = i->posY;
 #ifdef NGIFLIB_INDEXED_ONLY
```
