# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 293_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `293_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 70-110 of the vulnerable file.

		return;
	}

	if (OPENBASEDIR_CHECKPATH(link)) {
		RETURN_FALSE;
	}

	if (php_sys_readlink(link, target, MAXPATHLEN) == -1) {
		php_error_docref(NULL, E_WARNING, "readlink failed to read the symbolic link (%s), error %d)", link, GetLastError());
		RETURN_FALSE;
	}
	RETURN_STRING(target);
}
/* }}} */

/* {{{ proto int linkinfo(string filename)
   Returns the st_dev field of the UNIX C stat structure describing the link */
PHP_FUNCTION(linkinfo)
{
	char *link;
	size_t link_len;
	zend_stat_t sb;
	int ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "p", &link, &link_len) == FAILURE) {
		return;
	}

	ret = VCWD_STAT(link, &sb);
	if (ret == -1) {
		php_error_docref(NULL, E_WARNING, "%s", strerror(errno));
		RETURN_LONG(Z_L(-1));
	}

	RETURN_LONG((zend_long) sb.st_dev);
}
/* }}} */

/* {{{ proto int symlink(string target, string link)
   Create a symbolic link */
PHP_FUNCTION(symlink)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,6 +87,7 @@
 PHP_FUNCTION(linkinfo)
 {
 	char *link;
+	char *dirname;
 	size_t link_len;
 	zend_stat_t sb;
 	int ret;
@@ -95,12 +96,22 @@
 		return;
 	}
 
+	dirname = estrndup(link, link_len);
+	php_dirname(dirname, link_len);
+
+	if (php_check_open_basedir(dirname)) {
+		efree(dirname);
+		RETURN_FALSE;
+	}
+
 	ret = VCWD_STAT(link, &sb);
 	if (ret == -1) {
 		php_error_docref(NULL, E_WARNING, "%s", strerror(errno));
+		efree(dirname);
 		RETURN_LONG(Z_L(-1));
 	}
 
+	efree(dirname);
 	RETURN_LONG((zend_long) sb.st_dev);
 }
 /* }}} */
```
