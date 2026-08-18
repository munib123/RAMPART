# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3244_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3244_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 554-595 of the vulnerable file.

		 * BUT, to get into this branch of code, the name is too long,
		 * so we don't care. */
		xparam->inputs.namelen = sizeof(unix_addr->sun_path) - 1;
		php_error_docref(NULL, E_NOTICE,
			"socket path exceeded the maximum allowed length of %lu bytes "
			"and was truncated", (unsigned long)sizeof(unix_addr->sun_path));
	}

	memcpy(unix_addr->sun_path, xparam->inputs.name, xparam->inputs.namelen);

	return 1;
}
#endif

static inline char *parse_ip_address_ex(const char *str, size_t str_len, int *portno, int get_err, zend_string **err)
{
	char *colon;
	char *host = NULL;

#ifdef HAVE_IPV6
	char *p;

	if (*(str) == '[' && str_len > 1) {
		/* IPV6 notation to specify raw address with port (i.e. [fe80::1]:80) */
		p = memchr(str + 1, ']', str_len - 2);
		if (!p || *(p + 1) != ':') {
			if (get_err) {
				*err = strpprintf(0, "Failed to parse IPv6 address \"%s\"", str);
			}
			return NULL;
		}
		*portno = atoi(p + 2);
		return estrndup(str + 1, p - str - 1);
	}
#endif
	if (str_len) {
		colon = memchr(str, ':', str_len - 1);
	} else {
		colon = NULL;
	}
	if (colon) {
		*portno = atoi(colon + 1);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -571,37 +571,44 @@
 	char *host = NULL;
 
 #ifdef HAVE_IPV6
-	char *p;
-
 	if (*(str) == '[' && str_len > 1) {
 		/* IPV6 notation to specify raw address with port (i.e. [fe80::1]:80) */
-		p = memchr(str + 1, ']', str_len - 2);
+		char *p = memchr(str + 1, ']', str_len - 2), *e = NULL;
 		if (!p || *(p + 1) != ':') {
 			if (get_err) {
 				*err = strpprintf(0, "Failed to parse IPv6 address \"%s\"", str);
 			}
 			return NULL;
 		}
-		*portno = atoi(p + 2);
+		*portno = strtol(p + 2, &e, 10);
+		if (e && *e) {
+			if (get_err) {
+				*err = strpprintf(0, "Failed to parse address \"%s\"", str);
+			}
+			return NULL;
+		}
 		return estrndup(str + 1, p - str - 1);
 	}
 #endif
+
 	if (str_len) {
 		colon = memchr(str, ':', str_len - 1);
 	} else {
 		colon = NULL;
 	}
+
 	if (colon) {
-		*portno = atoi(colon + 1);
-		host = estrndup(str, colon - str);
-	} else {
-		if (get_err) {
-			*err = strpprintf(0, "Failed to parse address \"%s\"", str);
+		char *e = NULL;
+		*portno = strtol(colon + 1, &e, 10);
+		if (!e || !*e) {
+			return estrndup(str, colon - str);
 		}
-		return NULL;
-	}
-
-	return host;
+	}
+
+	if (get_err) {
+		*err = strpprintf(0, "Failed to parse address \"%s\"", str);
+	}
+	return NULL;
 }
 
 static inline char *parse_ip_address(php_stream_xport_param *xparam, int *portno)
```
