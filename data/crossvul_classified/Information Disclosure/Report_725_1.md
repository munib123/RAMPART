# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 725_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `725_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 182-222 of the vulnerable file.


			if ( version > PROTOCOL_UNKNOWN ) {

				memset(string, 0, sizeof(string));
				
				snprintf(string, sizeof(string), "Version: %d\nCapabilities: \n\n", version);

				univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "SEND: %s", string);

				write(fd, string, strlen(string));

			} else {
				
				univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "Capabilities recv, but no version line");
				
			}

			p+=strlen(network_line);


		} else if ( !strncmp(network_line, "GET_DN ", strlen("GET_DN ")) && msg_id != UINT32_MAX && network_client_get_version(fd) > 0) {

			univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "RECV: GET_DN");

			id=strtoul(&(network_line[strlen("GET_DN ")]), NULL, 10);

			univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "id: %ld",id);

			if ( id <= notify_last_id.id) {

				char *dn_string = NULL;

				univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "try to read %ld from cache", id);

				/* try to read from cache */
				if ( (dn_string = notifier_cache_get(id)) == NULL ) {

					univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "%ld not found in cache", id);

					univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "%ld get one dn", id);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -199,7 +199,7 @@
 			p+=strlen(network_line);
 
 
-		} else if ( !strncmp(network_line, "GET_DN ", strlen("GET_DN ")) && msg_id != UINT32_MAX && network_client_get_version(fd) > 0) {
+		} else if ( !strncmp(network_line, "GET_DN ", strlen("GET_DN ")) && msg_id != UINT32_MAX && version > PROTOCOL_UNKNOWN && version < PROTOCOL_3) {
 
 			univention_debug(UV_DEBUG_TRANSFILE, UV_DEBUG_ALL, "RECV: GET_DN");
 
```
