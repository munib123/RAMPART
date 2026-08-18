# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 107_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `107_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 511-551 of the vulnerable file.

#endif /* !defined(NGIFLIB_NO_FILE) */
			return 0;
		}
		if(npix==0) {
#if !defined(NGIFLIB_NO_FILE)
			if(i->parent && i->parent->log) fprintf(i->parent->log, "assez de pixels, On se casse !\n");
#endif /* !defined(NGIFLIB_NO_FILE) */
			return 1;
		}	
		if(act_code==clr) {
#if !defined(NGIFLIB_NO_FILE)
			if(i->parent && i->parent->log) fprintf(i->parent->log, "Code clear (free=%hu) npix=%ld\n", free, npix);
#endif /* !defined(NGIFLIB_NO_FILE) */
			/* clear */
			free = clr + 2;
			context.nbbit = i->imgbits + 1;
			context.max = clr + clr - 1; /* (1 << context.nbbit) - 1 */
			act_code = GetGifWord(i, &context);
			casspecial = (u8)act_code;
			old_code = act_code;
			WritePixel(i, &context, casspecial); npix--;
		} else {
			read_byt = act_code;
			if(act_code >= free) {	/* code pas encore dans alphabet */
/*				printf("Code pas dans alphabet : %d>=%d push %d\n", act_code, free, casspecial); */
				*(--stackp) = casspecial; /* dernier debut de chaine ! */
				act_code = old_code;
			}
/*			printf("actcode=%d\n", act_code); */
			while(act_code > clr) { /* code non concret */
				/* fillstackloop empile les suffixes ! */
				*(--stackp) = ab_suffx[act_code];
				act_code = ab_prfx[act_code];	/* prefixe */
			}
			/* act_code est concret */
			casspecial = (u8)act_code;	/* dernier debut de chaine ! */
			*(--stackp) = casspecial;	/* push on stack */
			WritePixels(i, &context, stackp, stack_top - stackp);	/* unstack all pixels at once */
			npix -= (stack_top - stackp);
			stackp = stack_top;
/*			putchar('\n'); */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -528,7 +528,8 @@
 			act_code = GetGifWord(i, &context);
 			casspecial = (u8)act_code;
 			old_code = act_code;
-			WritePixel(i, &context, casspecial); npix--;
+			if(npix > 0) WritePixel(i, &context, casspecial);
+			npix--;
 		} else {
 			read_byt = act_code;
 			if(act_code >= free) {	/* code pas encore dans alphabet */
@@ -545,7 +546,11 @@
 			/* act_code est concret */
 			casspecial = (u8)act_code;	/* dernier debut de chaine ! */
 			*(--stackp) = casspecial;	/* push on stack */
-			WritePixels(i, &context, stackp, stack_top - stackp);	/* unstack all pixels at once */
+			if(npix >= (stack_top - stackp)) {
+				WritePixels(i, &context, stackp, stack_top - stackp);	/* unstack all pixels at once */
+			} else if(npix > 0) {	/* "pixel overflow" */
+				WritePixels(i, &context, stackp, npix);
+			}
 			npix -= (stack_top - stackp);
 			stackp = stack_top;
 /*			putchar('\n'); */
```
