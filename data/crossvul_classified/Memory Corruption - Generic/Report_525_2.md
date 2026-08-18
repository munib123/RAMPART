# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 525_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `525_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 210-250 of the vulnerable file.

			if (res<0) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_CONTAINER, ("[FFMPEG Demuxer] Failed to set option %s:%s\n", frag, mid+1) );
			}
			mid[0] = '=';
		}
		if (!sep) break;
		sep[0] = ':';
		frag = sep+1;
	}
#endif
}


static Bool FFD_CanHandleURL(GF_InputService *plug, const char *url)
{
	Bool has_audio, has_video;
	s32 i;
	AVFormatContext *ctx;
	AVOutputFormat *fmt_out;
	Bool ret = GF_FALSE;
	char *ext, szName[1000], szExt[20];
	const char *szExtList;
	FFDemux *ffd;
	if (!plug || !url)
		return GF_FALSE;
	/*disable RTP/RTSP from ffmpeg*/
	if (!strnicmp(url, "rtsp://", 7)) return GF_FALSE;
	if (!strnicmp(url, "rtspu://", 8)) return GF_FALSE;
	if (!strnicmp(url, "rtp://", 6)) return GF_FALSE;
	if (!strnicmp(url, "plato://", 8)) return GF_FALSE;
	if (!strnicmp(url, "udp://", 6)) return GF_FALSE;
	if (!strnicmp(url, "tcp://", 6)) return GF_FALSE;
	if (!strnicmp(url, "data:", 5)) return GF_FALSE;

	ffd = (FFDemux*)plug->priv;

	strcpy(szName, url);
	ext = strrchr(szName, '#');
	if (ext) ext[0] = 0;
	ext = strrchr(szName, '?');
	if (ext) ext[0] = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -227,7 +227,7 @@
 	AVFormatContext *ctx;
 	AVOutputFormat *fmt_out;
 	Bool ret = GF_FALSE;
-	char *ext, szName[1000], szExt[20];
+	char *ext, szName[1024], szExt[20];
 	const char *szExtList;
 	FFDemux *ffd;
 	if (!plug || !url)
@@ -243,6 +243,9 @@
 
 	ffd = (FFDemux*)plug->priv;
 
+	if (strlen(url) >= sizeof(szName))
+		return GF_FALSE;
+
 	strcpy(szName, url);
 	ext = strrchr(szName, '#');
 	if (ext) ext[0] = 0;
@@ -252,7 +255,7 @@
 	ext = strrchr(szName, '.');
 	if (ext && strlen(ext) > 19) ext = NULL;
 
-	if (ext && strlen(ext) > 1) {
+	if (ext && strlen(ext) > 1 && strlen(ext) <= sizeof(szExt)) {
 		strcpy(szExt, &ext[1]);
 		strlwr(szExt);
 #ifndef FFMPEG_DEMUX_ENABLE_MPEG2TS
```
