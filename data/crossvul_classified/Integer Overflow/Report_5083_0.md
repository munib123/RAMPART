# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 5083_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5083_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 146-186 of the vulnerable file.

					MB_FAILURE(pos, 3);
				} else if (this_char >= 0xd800 && this_char <= 0xdfff) { /* surrogate */
					MB_FAILURE(pos, 3);
				}
				pos += 3;
			} else if (c < 0xf5) {
				size_t avail = str_len - pos;

				if (avail < 4 ||
						!utf8_trail(str[pos + 1]) || !utf8_trail(str[pos + 2]) ||
						!utf8_trail(str[pos + 3])) {
					if (avail < 2 || utf8_lead(str[pos + 1]))
						MB_FAILURE(pos, 1);
					else if (avail < 3 || utf8_lead(str[pos + 2]))
						MB_FAILURE(pos, 2);
					else if (avail < 4 || utf8_lead(str[pos + 3]))
						MB_FAILURE(pos, 3);
					else
						MB_FAILURE(pos, 4);
				}
				
				this_char = ((c & 0x07) << 18) | ((str[pos + 1] & 0x3f) << 12) | ((str[pos + 2] & 0x3f) << 6) | (str[pos + 3] & 0x3f);
				if (this_char < 0x10000 || this_char > 0x10FFFF) { /* non-shortest form or outside range */
					MB_FAILURE(pos, 4);
				}
				pos += 4;
			} else {
				MB_FAILURE(pos, 1);
			}
		}
		break;

	case cs_big5:
		/* reference http://demo.icu-project.org/icu-bin/convexp?conv=big5 */
		{
			unsigned char c = str[pos];
			if (c >= 0x81 && c <= 0xFE) {
				unsigned char next;
				if (!CHECK_LEN(pos, 2))
					MB_FAILURE(pos, 1);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -163,7 +163,7 @@
 					else
 						MB_FAILURE(pos, 4);
 				}
-				
+
 				this_char = ((c & 0x07) << 18) | ((str[pos + 1] & 0x3f) << 12) | ((str[pos + 2] & 0x3f) << 6) | (str[pos + 3] & 0x3f);
 				if (this_char < 0x10000 || this_char > 0x10FFFF) { /* non-shortest form or outside range */
 					MB_FAILURE(pos, 4);
@@ -437,7 +437,7 @@
 
 	if (charset_hint) {
 		int found = 0;
-		
+
 		/* now walk the charset map and look for the codeset */
 		for (i = 0; charset_map[i].codeset; i++) {
 			if (len == strlen(charset_map[i].codeset) && strncasecmp(charset_hint, charset_map[i].codeset, len) == 0) {
@@ -545,7 +545,7 @@
 		return 0;
 
 	code_key = (unsigned short) code_key_a;
-	
+
 	while (l <= h) {
 		m = l + (h - l) / 2;
 		if (code_key < m->un_code_point)
@@ -571,7 +571,7 @@
 		/* identity mapping of code points to unicode */
 		if (code > 0xFF) {
 			return FAILURE;
-		} 
+		}
 		*res = code;
 		break;
 
@@ -590,7 +590,7 @@
 			return FAILURE;
 		}
 		break;
-		
+
 	case cs_8859_15:
 		if (code < 0xA4 || (code > 0xBE && code <= 0xFF)) {
 			*res = code;
@@ -634,7 +634,7 @@
 	case cs_cp866:
 		table = unimap_cp866;
 		table_size = sizeof(unimap_cp866) / sizeof(*unimap_cp866);
-		
+
 table_over_7F:
 		if (code <= 0x7F) {
 			*res = code;
@@ -710,7 +710,7 @@
 	 * Not sure this is the relevant part for HTML 5, though. I opted to
 	 * disallow the characters that would result in a parse error when
 	 * preprocessing of the input stream. See also section 8.1.3.
-	 * 
+	 *
 	 * It's unclear if XHTML 1.0 allows C1 characters. I'll opt to apply to
 	 * XHTML 1.0 the same rules as for XML 1.0.
 	 * See <http://cmsmcq.com/2007/C1.xml>.
@@ -774,7 +774,7 @@
 /* {{{ process_numeric_entity
  * Auxiliary function to traverse_for_entities.
  * On input, *buf should point to the first character after # and on output, it's the last
- * byte read, no matter if there was success or insuccess. 
+ * byte read, no matter if there was success or insuccess.
  */
 static inline int process_numeric_entity(const char **buf, unsigned *code_point)
 {
@@ -784,7 +784,7 @@
 
 	if (hexadecimal && (**buf != '\0'))
 		(*buf)++;
-			
+
 	/* strtol allows whitespace and other stuff in the beginning
 		* we're not interested */
 	if ((hexadecimal && !isxdigit(**buf)) ||
@@ -969,7 +969,7 @@
 				goto invalid_code;
 
 			/* are we allowed to decode this entity in this document type?
-			 * HTML 5 is the only that has a character that cannot be used in 
+			 * HTML 5 is the only that has a character that cannot be used in
 			 * a numeric entity but is allowed literally (U+000D). The
 			 * unoptimized version would be ... || !numeric_entity_is_allowed(code) */
 			if (!unicode_cp_is_allowed(code, doctype) ||
@@ -996,9 +996,9 @@
 				}
 			}
 		}
-		
+
 		assert(*next == ';');
-		
+
 		if (((code == '\'' && !(flags & ENT_HTML_QUOTE_SINGLE)) ||
 				(code == '"' && !(flags & ENT_HTML_QUOTE_DOUBLE)))
 				/* && code2 == '\0' always true for current maps */)
@@ -1026,7 +1026,7 @@
 			*(q++) = *p;
 		}
 	}
-	
+
 	*q = '\0';
 	*retlen = (size_t)(q - ret);
 }
@@ -1066,7 +1066,7 @@
 	entity_table_opt retval = {NULL};
 
 	assert(!(doctype == ENT_HTML_DOC_XML1 && all));
-	
+
 	if (all) {
 		retval.ms_table = (doctype == ENT_HTML_DOC_HTML5) ?
 			entity_ms_table_html5 : entity_ms_table_html4;
@@ -1111,13 +1111,13 @@
 	if (retlen == 0) {
 		goto empty_source;
 	}
-	
+
 	inverse_map = unescape_inverse_map(all, flags);
-	
+
 	/* replace numeric entities */
 	traverse_for_entities(old, oldlen, ret, &retlen, all, flags, inverse_map, charset);
 
-empty_source:	
+empty_source:
 	*newlen = retlen;
 	return ret;
 }
@@ -1141,7 +1141,7 @@
 {
 	unsigned stage1_idx = ENT_STAGE1_INDEX(k);
 	const entity_stage3_row *c;
-	
+
 	if (stage1_idx > 0x1D) {
 		*entity     = NULL;
 		*entity_len = 0;
@@ -1162,7 +1162,7 @@
 		if (!(*cursor < oldlen))
 			goto no_suitable_2nd;
 
-		next_char = get_next_char(charset, old, oldlen, cursor, &status); 
+		next_char = get_next_char(charset, old, oldlen, cursor, &status);
 
 		if (status == FAILURE)
 			goto no_suitable_2nd;
@@ -1187,7 +1187,7 @@
 		*entity = (const unsigned char *)
 			c->data.multicodepoint_table[0].leading_entry.default_entity;
 		*entity_len = c->data.multicodepoint_table[0].leading_entry.default_entity_len;
-	}	
+	}
 }
 /* }}} */
 
@@ -1255,7 +1255,7 @@
 
 	/* initial estimate */
 	if (oldlen < 64) {
-		maxlen = 128;	
+		maxlen = 128;
 	} else {
 		maxlen = 2 * oldlen;
 		if (maxlen < oldlen) {
@@ -1444,6 +1444,10 @@
 	}
 
 	replaced = php_escape_html_entities_ex(str, str_len, &new_len, all, (int) flags, hint_charset, double_encode TSRMLS_CC);
+	if (new_len > INT_MAX) {
+		efree(replaced);
+		RETURN_FALSE;
+	}
 	RETVAL_STRINGL(replaced, (int)new_len, 0);
 }
 /* }}} */
@@ -1577,7 +1581,7 @@
 			} else {
 				spe_cp = uni_cp;
 			}
-			
+
 			written_k2 = write_octet_sequence(&key[written_k1], charset, spe_cp);
 			memcpy(&entity[1], mcpr[i].normal_entry.entity, l);
 			entity[l + 1] = ';';
@@ -1615,7 +1619,7 @@
 	LIMIT_ALL(all, doctype, charset);
 
 	array_init(return_value);
-	
+
 	entity_table = determine_entity_table(all, doctype);
 	if (all && !CHARSET_UNICODE_COMPAT(charset)) {
 		to_uni_table = enc_to_uni_index[charset];
```
