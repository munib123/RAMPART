# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 639_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `639_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 720-760 of the vulnerable file.

			/* all status codes in the 2xx range are defined by the specification as successful;
			 * all status codes in the 3xx range are for redirection, and so also should never
			 * fail */
			if (response_code >= 200 && response_code < 400) {
				reqok = 1;
			} else {
				switch(response_code) {
					case 403:
						php_stream_notify_error(context, PHP_STREAM_NOTIFY_AUTH_RESULT,
								tmp_line, response_code);
						break;
					default:
						/* safety net in the event tmp_line == NULL */
						if (!tmp_line_len) {
							tmp_line[0] = '\0';
						}
						php_stream_notify_error(context, PHP_STREAM_NOTIFY_FAILURE,
								tmp_line, response_code);
				}
			}
			if (tmp_line[tmp_line_len - 1] == '\n') {
				--tmp_line_len;
				if (tmp_line[tmp_line_len - 1] == '\r') {
					--tmp_line_len;
				}
			}
			MAKE_STD_ZVAL(http_response);
			ZVAL_STRINGL(http_response, tmp_line, tmp_line_len, 1);
			zend_hash_next_index_insert(Z_ARRVAL_P(response_header), &http_response, sizeof(zval *), NULL);
		}
	} else {
		php_stream_wrapper_log_error(wrapper, options TSRMLS_CC, "HTTP request failed, unexpected end of socket!");
		goto out;
	}

	/* read past HTTP headers */

	http_header_line = emalloc(HTTP_HEADER_BLOCK_SIZE);

	while (!body && !php_stream_eof(stream)) {
		size_t http_header_line_length;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -737,9 +737,9 @@
 								tmp_line, response_code);
 				}
 			}
-			if (tmp_line[tmp_line_len - 1] == '\n') {
+			if (tmp_line_len >= 1 && tmp_line[tmp_line_len - 1] == '\n') {
 				--tmp_line_len;
-				if (tmp_line[tmp_line_len - 1] == '\r') {
+				if (tmp_line_len >= 1 &&tmp_line[tmp_line_len - 1] == '\r') {
 					--tmp_line_len;
 				}
 			}
```
