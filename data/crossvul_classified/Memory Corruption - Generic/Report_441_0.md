# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 441_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `441_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 41-82 of the vulnerable file.


	/* Pattern not found */
	if (!clen || clen > buffer + size)
		return SIZE_MAX;

	/* Content-Length extraction */
	len = strtoul(clen + strlen(CONTENT_LENGTH), &end, 10);
	if (*end)
		return SIZE_MAX;

	return len;
}

/*
 * Return the http header error code. According
 * to rfc2616.6.1 status code is between HTTP_Version
 * and Reason_Phrase, separated by space caracter.
 */
int extract_status_code(char *buffer, size_t size)
{
	char *buf_code;
	char *begin;
	char *end = buffer + size;
	size_t inc = 0;
	int code;

	/* Allocate the room */
	buf_code = (char *)MALLOC(10);

	/* Status-Code extraction */
	while (buffer < end && *buffer++ != ' ') ;
	begin = buffer;
	while (buffer < end && *buffer++ != ' ')
		inc++;
	strncat(buf_code, begin, inc);
	code = atoi(buf_code);
	FREE(buf_code);
	return code;
}

/* simple function returning a pointer to the html buffer begin */
char *extract_html(char *buffer, size_t size_buffer)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,23 +58,18 @@
  */
 int extract_status_code(char *buffer, size_t size)
 {
-	char *buf_code;
-	char *begin;
 	char *end = buffer + size;
-	size_t inc = 0;
-	int code;
-
-	/* Allocate the room */
-	buf_code = (char *)MALLOC(10);
+	unsigned long code;
 
 	/* Status-Code extraction */
-	while (buffer < end && *buffer++ != ' ') ;
-	begin = buffer;
-	while (buffer < end && *buffer++ != ' ')
-		inc++;
-	strncat(buf_code, begin, inc);
-	code = atoi(buf_code);
-	FREE(buf_code);
+	while (buffer < end && *buffer != ' ' && *buffer != '\r')
+		buffer++;
+	buffer++;
+	if (buffer + 3 >= end || *buffer == ' ' || buffer[3] != ' ')
+		return 0;
+	code = strtoul(buffer, &end, 10);
+	if (buffer + 3 != end)
+		return 0;
 	return code;
 }
 
```
