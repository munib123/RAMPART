# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5116_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5116_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 7287-7327 of the vulnerable file.

 *       However, for performance reasons, recursion has been avoided
 *       where possible (tags without content within tags with content).
 *       This is achieved by means of the parsing_tag_content and tag_save*
 *       variables.
 *
 * NOTE: See above for known token mappings.
 *
 * NOTE: As tags can be opened and closed, a tag representation lookup
 *       may happen once or twice for a given tag. For efficiency reasons,
 *       the literal tag value is stored and used throughout the code.
 *       With the introduction of code page support, this solution is robust
 *       as the lookup only occurs once, removing the need for storage of
 *       the used code page.
 */
static guint32
parse_wbxml_tag_defined (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
			 guint32 str_tbl, guint8 *level, guint8 *codepage_stag, guint8 *codepage_attr,
			 const wbxml_decoding *map)
{
	guint32     tvb_len  = tvb_reported_length (tvb);
	guint32     off      = offset;
	guint32     len;
	guint       str_len;
	guint32     ent;
	guint32     idx;
	guint8      peek;
	guint32     tag_len;                     /* Length of the index (uintvar) from a LITERAL tag */
	guint8      tag_save_known      = 0;     /* Will contain peek & 0x3F (tag identity) */
	guint8      tag_new_known       = 0;     /* Will contain peek & 0x3F (tag identity) */
	const char *tag_save_literal;            /* Will contain the LITERAL tag identity */
	const char *tag_new_literal;             /* Will contain the LITERAL tag identity */
	guint8      parsing_tag_content = FALSE; /* Are we parsing content from a
					            tag with content: <x>Content</x>

					            The initial state is FALSE.
					            This state will trigger recursion. */
	tag_save_literal = NULL;                 /* Prevents compiler warning */

	DebugLog(("parse_wbxml_tag_defined (level = %u, offset = %u)\n", *level, offset));
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7304,7 +7304,7 @@
 			 const wbxml_decoding *map)
 {
 	guint32     tvb_len  = tvb_reported_length (tvb);
-	guint32     off      = offset;
+	guint32     off      = offset, last_off;
 	guint32     len;
 	guint       str_len;
 	guint32     ent;
@@ -7323,6 +7323,7 @@
 	tag_save_literal = NULL;                 /* Prevents compiler warning */
 
 	DebugLog(("parse_wbxml_tag_defined (level = %u, offset = %u)\n", *level, offset));
+	last_off = off;
 	while (off < tvb_len) {
 		peek = tvb_get_guint8 (tvb, off);
 		DebugLog(("STAG: (top of while) level = %3u, peek = 0x%02X, off = %u, tvb_len = %u\n", *level, peek, off, tvb_len));
@@ -7694,6 +7695,10 @@
 				/* TODO: Do I have to reset code page here? */
 			}
 		} /* if (tag & 0x3F) >= 5 */
+		if (off < last_off) {
+			THROW(ReportedBoundsError);
+		}
+		last_off = off;
 	} /* while */
 	DebugLog(("STAG: level = %u, Return: len = %u (end of function body)\n", *level, off - offset));
 	return (off - offset);
@@ -7711,7 +7716,7 @@
 		 guint8 *codepage_stag, guint8 *codepage_attr)
 {
 	guint32     tvb_len             = tvb_reported_length (tvb);
-	guint32     off                 = offset;
+	guint32     off                 = offset, last_off;
 	guint32     len;
 	guint       str_len;
 	guint32     ent;
@@ -7732,6 +7737,7 @@
 	tag_save_literal = NULL;                 /* Prevents compiler warning */
 
 	DebugLog(("parse_wbxml_tag (level = %u, offset = %u)\n", *level, offset));
+	last_off = off;
 	while (off < tvb_len) {
 		peek = tvb_get_guint8 (tvb, off);
 		DebugLog(("STAG: (top of while) level = %3u, peek = 0x%02X, off = %u, tvb_len = %u\n", *level, peek, off, tvb_len));
@@ -8091,6 +8097,10 @@
 				/* TODO: Do I have to reset code page here? */
 			}
 		} /* if (tag & 0x3F) >= 5 */
+		if (off < last_off) {
+			THROW(ReportedBoundsError);
+		}
+		last_off = off;
 	} /* while */
 	DebugLog(("STAG: level = %u, Return: len = %u (end of function body)\n",
 		  *level, off - offset));
@@ -8126,7 +8136,7 @@
 				    const wbxml_decoding *map)
 {
 	guint32     tvb_len = tvb_reported_length (tvb);
-	guint32     off     = offset;
+	guint32     off     = offset, last_off;
 	guint32     len;
 	guint       str_len;
 	guint32     ent;
@@ -8138,6 +8148,7 @@
 	DebugLog(("parse_wbxml_attr_defined (level = %u, offset = %u)\n",
 		  level, offset));
 	/* Parse attributes */
+	last_off = off;
 	while (off < tvb_len) {
 		peek = tvb_get_guint8 (tvb, off);
 		DebugLog(("ATTR: (top of while) level = %3u, peek = 0x%02X, "
@@ -8330,6 +8341,10 @@
 				off++;
 			}
 		}
+		if (off < last_off) {
+			THROW(ReportedBoundsError);
+		}
+		last_off = off;
 	} /* End WHILE */
 	DebugLog(("ATTR: level = %u, Return: len = %u (end of function body)\n",
 		  level, off - offset));
@@ -8350,7 +8365,7 @@
 			    guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr)
 {
 	guint32 tvb_len = tvb_reported_length (tvb);
-	guint32 off     = offset;
+	guint32 off     = offset, last_off;
 	guint32 len;
 	guint   str_len;
 	guint32 ent;
@@ -8359,6 +8374,7 @@
 
 	DebugLog(("parse_wbxml_attr (level = %u, offset = %u)\n", level, offset));
 	/* Parse attributes */
+	last_off = off;
 	while (off < tvb_len) {
 		peek = tvb_get_guint8 (tvb, off);
 		DebugLog(("ATTR: (top of while) level = %3u, peek = 0x%02X, "
@@ -8516,6 +8532,10 @@
 				off++;
 			}
 		}
+		if (off < last_off) {
+			THROW(ReportedBoundsError);
+		}
+		last_off = off;
 	} /* End WHILE */
 	DebugLog(("ATTR: level = %u, Return: len = %u (end of function body)\n",
 		  level, off - offset));
```
