# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5675_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5675_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 741-783 of the vulnerable file.

	char *key,
	char *value,
	struct iscsi_param_list *param_list)
{
	struct iscsi_extra_response *extra_response;

	if (strlen(value) > VALUE_MAXLEN) {
		pr_err("Value for notunderstood key \"%s\" exceeds %d,"
			" protocol error.\n", key, VALUE_MAXLEN);
		return -1;
	}

	extra_response = kzalloc(sizeof(struct iscsi_extra_response), GFP_KERNEL);
	if (!extra_response) {
		pr_err("Unable to allocate memory for"
			" struct iscsi_extra_response.\n");
		return -1;
	}
	INIT_LIST_HEAD(&extra_response->er_list);

	strncpy(extra_response->key, key, strlen(key) + 1);
	strncpy(extra_response->value, NOTUNDERSTOOD,
			strlen(NOTUNDERSTOOD) + 1);

	list_add_tail(&extra_response->er_list,
			&param_list->extra_response_list);
	return 0;
}

static int iscsi_check_for_auth_key(char *key)
{
	/*
	 * RFC 1994
	 */
	if (!strcmp(key, "CHAP_A") || !strcmp(key, "CHAP_I") ||
	    !strcmp(key, "CHAP_C") || !strcmp(key, "CHAP_N") ||
	    !strcmp(key, "CHAP_R"))
		return 1;

	/*
	 * RFC 2945
	 */
	if (!strcmp(key, "SRP_U") || !strcmp(key, "SRP_N") ||
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -758,9 +758,9 @@
 	}
 	INIT_LIST_HEAD(&extra_response->er_list);
 
-	strncpy(extra_response->key, key, strlen(key) + 1);
-	strncpy(extra_response->value, NOTUNDERSTOOD,
-			strlen(NOTUNDERSTOOD) + 1);
+	strlcpy(extra_response->key, key, sizeof(extra_response->key));
+	strlcpy(extra_response->value, NOTUNDERSTOOD,
+		sizeof(extra_response->value));
 
 	list_add_tail(&extra_response->er_list,
 			&param_list->extra_response_list);
@@ -1629,8 +1629,6 @@
 
 		if (phase & PHASE_SECURITY) {
 			if (iscsi_check_for_auth_key(key) > 0) {
-				char *tmpptr = key + strlen(key);
-				*tmpptr = '=';
 				kfree(tmpbuf);
 				return 1;
 			}
```
