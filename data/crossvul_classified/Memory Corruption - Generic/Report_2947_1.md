# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2947_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2947_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2104-2144 of the vulnerable file.

	    xmlPopInput(ctxt);
}

#define SKIP_BLANKS xmlSkipBlankChars(ctxt)

#define NEXT xmlNextChar(ctxt)

#define NEXT1 {								\
	ctxt->input->col++;						\
	ctxt->input->cur++;						\
	ctxt->nbChars++;						\
	if (*ctxt->input->cur == 0)					\
	    xmlParserInputGrow(ctxt->input, INPUT_CHUNK);		\
    }

#define NEXTL(l) do {							\
    if (*(ctxt->input->cur) == '\n') {					\
	ctxt->input->line++; ctxt->input->col = 1;			\
    } else ctxt->input->col++;						\
    ctxt->input->cur += l;				\
    if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);	\
  } while (0)

#define CUR_CHAR(l) xmlCurrentChar(ctxt, &l)
#define CUR_SCHAR(s, l) xmlStringCurrentChar(ctxt, s, &l)

#define COPY_BUF(l,b,i,v)						\
    if (l == 1) b[i++] = (xmlChar) v;					\
    else i += xmlCopyCharMultiByte(&b[i],v)

/**
 * xmlSkipBlankChars:
 * @ctxt:  the XML parser context
 *
 * skip all blanks character found at that point in the input streams.
 * It pops up finished entities in the process if allowable at that point.
 *
 * Returns the number of space chars skipped
 */

int
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2121,7 +2121,6 @@
 	ctxt->input->line++; ctxt->input->col = 1;			\
     } else ctxt->input->col++;						\
     ctxt->input->cur += l;				\
-    if (*ctxt->input->cur == '%') xmlParserHandlePEReference(ctxt);	\
   } while (0)
 
 #define CUR_CHAR(l) xmlCurrentChar(ctxt, &l)
@@ -3412,19 +3411,22 @@
 	    len += l;
 	    NEXTL(l);
 	    c = CUR_CHAR(l);
-	    if (c == 0) {
-		count = 0;
-		GROW;
-                if (ctxt->instate == XML_PARSER_EOF)
-                    return(NULL);
-		c = CUR_CHAR(l);
-	    }
 	}
     }
     if ((len > XML_MAX_NAME_LENGTH) &&
         ((ctxt->options & XML_PARSE_HUGE) == 0)) {
         xmlFatalErr(ctxt, XML_ERR_NAME_TOO_LONG, "Name");
         return(NULL);
+    }
+    if (ctxt->input->cur - ctxt->input->base < len) {
+        /*
+         * There were a couple of bugs where PERefs lead to to a change
+         * of the buffer. Check the buffer size to avoid passing an invalid
+         * pointer to xmlDictLookup.
+         */
+        xmlFatalErr(ctxt, XML_ERR_INTERNAL_ERROR,
+                    "unexpected change of input buffer");
+        return (NULL);
     }
     if ((*ctxt->input->cur == '\n') && (ctxt->input->cur[-1] == '\r'))
         return(xmlDictLookup(ctxt->dict, ctxt->input->cur - (len + 1), len));
```
