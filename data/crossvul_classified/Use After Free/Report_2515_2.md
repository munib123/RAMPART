# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 2515_2
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2515_2`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 1-22 of the vulnerable file.

/*
 * $LynxId: HTML.c,v 1.173 2017/07/04 20:05:01 tom Exp $
 *
 *		Structured stream to Rich hypertext converter
 *		============================================
 *
 *	This generates a hypertext object.  It converts from the
 *	structured stream interface of HTML events into the style-
 *	oriented interface of the HText.h interface.  This module is
 *	only used in clients and should not be linked into servers.
 *
 *	Override this module if making a new GUI browser.
 *
 *   Being Overidden
 *
 */

#define HTSTREAM_INTERNAL 1

#include <HTUtils.h>

#define Lynx_HTML_Handler
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,5 +1,5 @@
 /*
- * $LynxId: HTML.c,v 1.173 2017/07/04 20:05:01 tom Exp $
+ * $LynxId: HTML.c,v 1.174 2017/07/05 22:48:09 tom Exp $
  *
  *		Structured stream to Rich hypertext converter
  *		============================================
@@ -505,6 +505,8 @@
  */
 void HTML_put_string(HTStructured * me, const char *s)
 {
+    HTChunk *target = NULL;
+
 #ifdef USE_PRETTYSRC
     char *translated_string = NULL;
 #endif
@@ -525,15 +527,15 @@
 	break;			/* Do Nothing */
 
     case HTML_TITLE:
-	HTChunkPuts(&me->title, s);
+	target = &me->title;
 	break;
 
     case HTML_STYLE:
-	HTChunkPuts(&me->style_block, s);
+	target = &me->style_block;
 	break;
 
     case HTML_SCRIPT:
-	HTChunkPuts(&me->script, s);
+	target = &me->script;
 	break;
 
     case HTML_PRE:		/* Formatted text */
@@ -547,20 +549,20 @@
 	break;
 
     case HTML_OBJECT:
-	HTChunkPuts(&me->object, s);
+	target = &me->object;
 	break;
 
     case HTML_TEXTAREA:
-	HTChunkPuts(&me->textarea, s);
+	target = &me->textarea;
 	break;
 
     case HTML_SELECT:
     case HTML_OPTION:
-	HTChunkPuts(&me->option, s);
+	target = &me->option;
 	break;
 
     case HTML_MATH:
-	HTChunkPuts(&me->math, s);
+	target = &me->math;
 	break;
 
     default:			/* Free format text? */
@@ -651,6 +653,15 @@
 	    }			/* for */
 	}
     }				/* end switch */
+
+    if (target != NULL) {
+	if (target->data == s) {
+	    CTRACE((tfp, "BUG: appending chunk to itself: `%.*s'\n",
+		    target->size, target->data));
+	} else {
+	    HTChunkPuts(target, s);
+	}
+    }
 #ifdef USE_PRETTYSRC
     if (psrc_convert_string) {
 	psrc_convert_string = FALSE;
```
