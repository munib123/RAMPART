# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 3266_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3266_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 6001-6041 of the vulnerable file.


void Lua::setParamsTable(lua_State* vm, const char* table_name,
			 const char* query) const {
  char outbuf[FILENAME_MAX];
  char *where;
  char *tok;

  char *query_string = query ? strdup(query) : NULL;

  lua_newtable(L);

  if (query_string) {
    // ntop->getTrace()->traceEvent(TRACE_WARNING, "[HTTP] %s", query_string);

    tok = strtok_r(query_string, "&", &where);

    while(tok != NULL) {
      char *_equal;

      if(strncmp(tok, "csrf", strlen("csrf")) /* Do not put csrf into the params table */
	 && (_equal = strchr(tok, '='))) {
	char *decoded_buf;
        int len;

        _equal[0] = '\0';
        _equal = &_equal[1];
        len = strlen(_equal);

        purifyHTTPParameter(tok), purifyHTTPParameter(_equal);

        // ntop->getTrace()->traceEvent(TRACE_WARNING, "%s = %s", tok, _equal);

        if((decoded_buf = (char*)malloc(len+1)) != NULL) {

          Utils::urlDecode(_equal, decoded_buf, len+1);

	  Utils::purifyHTTPparam(tok, true, false);
	  Utils::purifyHTTPparam(decoded_buf, false, false);

	  /* Now make sure that decoded_buf is not a file path */
	  FILE *fd;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6018,7 +6018,8 @@
       char *_equal;
 
       if(strncmp(tok, "csrf", strlen("csrf")) /* Do not put csrf into the params table */
-	 && (_equal = strchr(tok, '='))) {
+	 && (_equal = strchr(tok, '='))
+	 && (strlen(_equal) > 1)) {
 	char *decoded_buf;
         int len;
 
```
