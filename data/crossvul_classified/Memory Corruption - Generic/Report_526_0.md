# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 526_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `526_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1698-1738 of the vulnerable file.

			fprintf(stderr, "Input url %s is too long, truncating to %d chars.\n", url_arg, (int)(sizeof(the_url) - 1));
			strncpy(the_url, url_arg, sizeof(the_url)-1);
			the_url[sizeof(the_url) - 1] = 0;
		}
		else {
			strcpy(the_url, url_arg);
		}
		ext = strrchr(the_url, '.');
		if (ext && (!stricmp(ext, ".m3u") || !stricmp(ext, ".pls"))) {
			GF_Err e = GF_OK;
			fprintf(stderr, "Opening Playlist %s\n", the_url);

			strcpy(pl_path, the_url);
			/*this is not clean, we need to have a plugin handle playlist for ourselves*/
			if (!strncmp("http:", the_url, 5)) {
				GF_DownloadSession *sess = gf_dm_sess_new(term->downloader, the_url, GF_NETIO_SESSION_NOT_THREADED, NULL, NULL, &e);
				if (sess) {
					e = gf_dm_sess_process(sess);
					if (!e) {
						strncpy(the_url, gf_dm_sess_get_cache_name(sess), sizeof(the_url) - 1);
						the_url[sizeof(the_cfg) - 1] = 0;
					}
					gf_dm_sess_del(sess);
				}
			}

			playlist = e ? NULL : gf_fopen(the_url, "rt");
			readonly_playlist = 1;
			if (playlist) {
				request_next_playlist_item = GF_TRUE;
			} else {
				if (e)
					fprintf(stderr, "Failed to open playlist %s: %s\n", the_url, gf_error_to_string(e) );
				fprintf(stderr, "Hit 'h' for help\n\n");
			}
		} else {
			fprintf(stderr, "Opening URL %s\n", the_url);
			if (pause_at_first) fprintf(stderr, "[Status: Paused]\n");
			gf_term_connect_from_time(term, the_url, (u64) (play_from*1000), pause_at_first);
		}
	} else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1715,7 +1715,7 @@
 					e = gf_dm_sess_process(sess);
 					if (!e) {
 						strncpy(the_url, gf_dm_sess_get_cache_name(sess), sizeof(the_url) - 1);
-						the_url[sizeof(the_cfg) - 1] = 0;
+						the_url[sizeof(the_url) - 1] = 0;
 					}
 					gf_dm_sess_del(sess);
 				}
```
