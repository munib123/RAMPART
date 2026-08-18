# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4042_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4042_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 265-307 of the vulnerable file.

 *	Parameters :
 *		service_table *table ;	service table
 *		char * eventURLPath ;	event URL path used to find a service
 *								from the table
 *
 *	Description :	Traverses the service table and finds the node whose
 *		event URL Path matches a know value
 *
 *	Return : service_info * - pointer to the service list node from the
 *		service table whose event URL matches a known event URL;
 *
 *	Note :
 ************************************************************************/
service_info *FindServiceEventURLPath(
	service_table *table, const char *eventURLPath)
{
	service_info *finger = NULL;
	uri_type parsed_url;
	uri_type parsed_url_in;

	if (table &&
		parse_uri(eventURLPath, strlen(eventURLPath), &parsed_url_in) ==
			HTTP_SUCCESS) {
		finger = table->serviceList;
		while (finger) {
			if (finger->eventURL) {
				if (parse_uri(finger->eventURL,
					    strlen(finger->eventURL),
					    &parsed_url) == HTTP_SUCCESS) {
					if (!token_cmp(&parsed_url.pathquery,
						    &parsed_url_in.pathquery)) {
						return finger;
					}
				}
			}
			finger = finger->next;
		}
	}

	return NULL;
}
	#endif /* EXCLUDE_GENA */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -282,9 +282,11 @@
 	uri_type parsed_url;
 	uri_type parsed_url_in;
 
-	if (table &&
-		parse_uri(eventURLPath, strlen(eventURLPath), &parsed_url_in) ==
-			HTTP_SUCCESS) {
+	if (!table || !eventURLPath) {
+		return NULL;
+	}
+	if (parse_uri(eventURLPath, strlen(eventURLPath), &parsed_url_in) ==
+		HTTP_SUCCESS) {
 		finger = table->serviceList;
 		while (finger) {
 			if (finger->eventURL) {
@@ -327,9 +329,11 @@
 	uri_type parsed_url;
 	uri_type parsed_url_in;
 
-	if (table && parse_uri(controlURLPath,
-			     strlen(controlURLPath),
-			     &parsed_url_in) == HTTP_SUCCESS) {
+	if (!table || !controlURLPath) {
+		return NULL;
+	}
+	if (parse_uri(controlURLPath, strlen(controlURLPath), &parsed_url_in) ==
+		HTTP_SUCCESS) {
 		finger = table->serviceList;
 		while (finger) {
 			if (finger->controlURL) {
```
