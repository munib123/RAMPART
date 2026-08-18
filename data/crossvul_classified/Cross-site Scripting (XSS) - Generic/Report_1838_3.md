# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in c
**Pair ID:** 1838_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1838_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```c
Lines 726-772 of the vulnerable file.

	}
	
	if (op == SAPI_HEADER_DELETE) {
		if (strchr(header_line, ':')) {
			efree(header_line);
			sapi_module.sapi_error(E_WARNING, "Header to delete may not contain colon.");
			return FAILURE;
		}
		if (sapi_module.header_handler) {
			sapi_header.header = header_line;
			sapi_header.header_len = header_line_len;
			sapi_module.header_handler(&sapi_header, op, &SG(sapi_headers) TSRMLS_CC);
		}
		sapi_remove_header(&SG(sapi_headers).headers, header_line, header_line_len);
		efree(header_line);
		return SUCCESS;
	} else {
		/* new line/NUL character safety check */
		int i;
		for (i = 0; i < header_line_len; i++) {
			/* RFC 2616 allows new lines if followed by SP or HT */
			int illegal_break =
					(header_line[i+1] != ' ' && header_line[i+1] != '\t')
					&& (
						header_line[i] == '\n'
						|| (header_line[i] == '\r' && header_line[i+1] != '\n'));
			if (illegal_break) {
				efree(header_line);
				sapi_module.sapi_error(E_WARNING, "Header may not contain "
						"more than a single header, new line detected");
				return FAILURE;
			}
			if (header_line[i] == '\0') {
				efree(header_line);
				sapi_module.sapi_error(E_WARNING, "Header may not contain NUL bytes");
				return FAILURE;
			}
		}
	}

	sapi_header.header = header_line;
	sapi_header.header_len = header_line_len;

	/* Check the header for a few cases that we have special support for in SAPI */
	if (header_line_len>=5 
		&& !strncasecmp(header_line, "HTTP/", 5)) {
		/* filter out the response code */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -743,13 +743,8 @@
 		/* new line/NUL character safety check */
 		int i;
 		for (i = 0; i < header_line_len; i++) {
-			/* RFC 2616 allows new lines if followed by SP or HT */
-			int illegal_break =
-					(header_line[i+1] != ' ' && header_line[i+1] != '\t')
-					&& (
-						header_line[i] == '\n'
-						|| (header_line[i] == '\r' && header_line[i+1] != '\n'));
-			if (illegal_break) {
+			/* RFC 7230 ch. 3.2.4 deprecates folding support */
+			if (header_line[i] == '\n' || header_line[i] == '\r') {
 				efree(header_line);
 				sapi_module.sapi_error(E_WARNING, "Header may not contain "
 						"more than a single header, new line detected");
```
