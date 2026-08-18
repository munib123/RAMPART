# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 525_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `525_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 893-933 of the vulnerable file.

	return 1;

	case GF_EVENT_QUIT:
		if (evt->message.error)  {
			fprintf(stderr, "A fatal error was encoutered: %s (%s) - exiting ...\n", evt->message.message ? evt->message.message : "no details", gf_error_to_string(evt->message.error) );
		}
		Run = 0;
		break;
	case GF_EVENT_DISCONNECT:
		gf_term_disconnect(term);
		break;
	case GF_EVENT_MIGRATE:
	{
	}
	break;
	case GF_EVENT_NAVIGATE_INFO:
		if (evt->navigate.to_url) fprintf(stderr, "Go to URL: \"%s\"\r", evt->navigate.to_url);
		break;
	case GF_EVENT_NAVIGATE:
		if (gf_term_is_supported_url(term, evt->navigate.to_url, 1, no_mime_check)) {
			strcpy(the_url, evt->navigate.to_url);
			fprintf(stderr, "Navigating to URL %s\n", the_url);
			gf_term_navigate_to(term, evt->navigate.to_url);
			return 1;
		} else {
			fprintf(stderr, "Navigation destination not supported\nGo to URL: %s\n", evt->navigate.to_url);
		}
		break;
	case GF_EVENT_SET_CAPTION:
		gf_term_user_event(term, evt);
		break;
	case GF_EVENT_AUTHORIZATION:
	{
		int maxTries = 1;
		assert( evt->type == GF_EVENT_AUTHORIZATION);
		assert( evt->auth.user);
		assert( evt->auth.password);
		assert( evt->auth.site_url);
		while ((!strlen(evt->auth.user) || !strlen(evt->auth.password)) && (maxTries--) >= 0) {
			fprintf(stderr, "**** Authorization required for site %s ****\n", evt->auth.site_url);
			fprintf(stderr, "login   : ");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -910,7 +910,8 @@
 		break;
 	case GF_EVENT_NAVIGATE:
 		if (gf_term_is_supported_url(term, evt->navigate.to_url, 1, no_mime_check)) {
-			strcpy(the_url, evt->navigate.to_url);
+			strncpy(the_url, evt->navigate.to_url, sizeof(the_url)-1);
+			the_url[sizeof(the_url) - 1] = 0;
 			fprintf(stderr, "Navigating to URL %s\n", the_url);
 			gf_term_navigate_to(term, evt->navigate.to_url);
 			return 1;
@@ -1099,6 +1100,11 @@
 	}
 	{
 		const size_t sepIdx = sep - opt_string;
+		if (sepIdx >= sizeof(szSec)) {
+			fprintf(stderr, "Badly formatted option %s - Section name is too long\n", opt_string);
+			return;
+		}
+
 		strncpy(szSec, opt_string, sepIdx);
 		szSec[sepIdx] = 0;
 	}
@@ -1110,8 +1116,16 @@
 	}
 	{
 		const size_t sepIdx = sep2 - sep;
+		if (sepIdx >= sizeof(szKey)) {
+			fprintf(stderr, "Badly formatted option %s - key name is too long\n", opt_string);
+			return;
+		}
 		strncpy(szKey, sep, sepIdx);
 		szKey[sepIdx] = 0;
+		if (strlen(sep2 + 1) >= sizeof(szVal)) {
+			fprintf(stderr, "Badly formatted option %s - value is too long\n", opt_string);
+			return;
+		}
 		strcpy(szVal, sep2+1);
 	}
 
@@ -1680,7 +1694,14 @@
 	else if (!gui_mode && url_arg) {
 		char *ext;
 
-		strcpy(the_url, url_arg);
+		if (strlen(url_arg) >= sizeof(the_url)) {
+			fprintf(stderr, "Input url %s is too long, truncating to %d chars.\n", url_arg, (int)(sizeof(the_url) - 1));
+			strncpy(the_url, url_arg, sizeof(the_url)-1);
+			the_url[sizeof(the_url) - 1] = 0;
+		}
+		else {
+			strcpy(the_url, url_arg);
+		}
 		ext = strrchr(the_url, '.');
 		if (ext && (!stricmp(ext, ".m3u") || !stricmp(ext, ".pls"))) {
 			GF_Err e = GF_OK;
@@ -1692,7 +1713,10 @@
 				GF_DownloadSession *sess = gf_dm_sess_new(term->downloader, the_url, GF_NETIO_SESSION_NOT_THREADED, NULL, NULL, &e);
 				if (sess) {
 					e = gf_dm_sess_process(sess);
-					if (!e) strcpy(the_url, gf_dm_sess_get_cache_name(sess));
+					if (!e) {
+						strncpy(the_url, gf_dm_sess_get_cache_name(sess), sizeof(the_url) - 1);
+						the_url[sizeof(the_cfg) - 1] = 0;
+					}
 					gf_dm_sess_del(sess);
 				}
 			}
@@ -1715,7 +1739,8 @@
 		fprintf(stderr, "Hit 'h' for help\n\n");
 		str = gf_cfg_get_key(cfg_file, "General", "StartupFile");
 		if (str) {
-			strcpy(the_url, "MP4Client "GPAC_FULL_VERSION);
+			strncpy(the_url, "MP4Client "GPAC_FULL_VERSION , sizeof(the_url)-1);
+			the_url[sizeof(the_url) - 1] = 0;
 			gf_term_connect(term, str);
 			startup_file = 1;
 			is_connected = 1;
```
