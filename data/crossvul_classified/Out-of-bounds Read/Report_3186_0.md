# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 3186_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3186_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 428-469 of the vulnerable file.

		if(q == NULL) {
			m->numberOfArguments--;
			return;
		}
		m->mimeArguments = q;
	}

	p = m->mimeArguments[offset] = rfc2231(arg);
	if(!p) {
		/* problem inside rfc2231() */
		cli_dbgmsg("messageAddArgument, error from rfc2231()\n");
		return;
	}

	if(strchr(p, '=') == NULL) {
		if(strncmp(p, "filename", 8) == 0) {
			/*
			 * FIXME: Bounce message handling is corrupting the in
			 * core copies of headers
			 */
			cli_dbgmsg("Possible data corruption fixed\n");
			p[8] = '=';
		} else {
			if(*p)
				cli_dbgmsg("messageAddArgument, '%s' contains no '='\n", p);
			free(m->mimeArguments[offset]);
			m->mimeArguments[offset] = NULL;
			return;
		}
	}

	/*
	 * This is terribly broken from an RFC point of view but is useful
	 * for catching viruses which have a filename but no type of
	 * mime. By pretending defaulting to an application rather than
	 * to nomime we can ensure they're saved and scanned
	 */
	if((strncasecmp(p, "filename=", 9) == 0) || (strncasecmp(p, "name=", 5) == 0))
		if(messageGetMimeType(m) == NOMIME) {
			cli_dbgmsg("Force mime encoding to application\n");
			messageSetMimeType(m, "application");
		}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -445,8 +445,12 @@
 			 * FIXME: Bounce message handling is corrupting the in
 			 * core copies of headers
 			 */
-			cli_dbgmsg("Possible data corruption fixed\n");
-			p[8] = '=';
+                        if (strlen(p) > 8) {
+                            cli_dbgmsg("Possible data corruption fixed\n");
+                            p[8] = '=';
+                        } else {
+                            cli_dbgmsg("Possible data corruption not fixed\n");
+                        }
 		} else {
 			if(*p)
 				cli_dbgmsg("messageAddArgument, '%s' contains no '='\n", p);
@@ -682,7 +686,7 @@
 				cli_dbgmsg("messageFindArgument: no '=' sign found in MIME header '%s' (%s)\n", variable, messageGetArgument(m, i));
 				return NULL;
 			}
-			if((*++ptr == '"') && (strchr(&ptr[1], '"') != NULL)) {
+			if((strlen(ptr) > 2) && (*++ptr == '"') && (strchr(&ptr[1], '"') != NULL)) {
 				/* Remove any quote characters */
 				char *ret = cli_strdup(++ptr);
 				char *p;
```
