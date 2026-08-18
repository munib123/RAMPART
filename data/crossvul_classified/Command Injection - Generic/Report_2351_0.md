# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 2351_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2351_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 235-276 of the vulnerable file.

}

/*
 * Extract a tag of the form NAME="value" from the line.
 */
static int parse_token(char **name, char **value, char **cp)
{
	char *end;

	if (!name || !value || !cp)
		return -BLKID_ERR_PARAM;

	if (!(*value = strchr(*cp, '=')))
		return 0;

	**value = '\0';
	*name = strip_line(*cp);
	*value = skip_over_blank(*value + 1);

	if (**value == '"') {
		end = strchr(*value + 1, '"');
		if (!end) {
			DBG(READ, ul_debug("unbalanced quotes at: %s", *value));
			*cp = *value;
			return -BLKID_ERR_CACHE;
		}
		(*value)++;
		*end = '\0';
		end++;
	} else {
		end = skip_over_word(*value);
		if (*end) {
			*end = '\0';
			end++;
		}
	}
	*cp = end;

	return 1;
}

/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -252,15 +252,30 @@
 	*value = skip_over_blank(*value + 1);
 
 	if (**value == '"') {
-		end = strchr(*value + 1, '"');
-		if (!end) {
+		char *p = end = *value + 1;
+
+		/* convert 'foo\"bar'  to 'foo"bar' */
+		while (*p) {
+			if (*p == '\\') {
+				p++;
+				*end = *p;
+			} else {
+				*end = *p;
+				if (*p == '"')
+					break;
+			}
+			p++;
+			end++;
+		}
+
+		if (*end != '"') {
 			DBG(READ, ul_debug("unbalanced quotes at: %s", *value));
 			*cp = *value;
 			return -BLKID_ERR_CACHE;
 		}
 		(*value)++;
 		*end = '\0';
-		end++;
+		end = ++p;
 	} else {
 		end = skip_over_word(*value);
 		if (*end) {
```
