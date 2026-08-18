# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3416_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3416_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 187-227 of the vulnerable file.

    AVFormatContext *ctx;
    int n_variants;
    struct variant **variants;
    int n_playlists;
    struct playlist **playlists;
    int n_renditions;
    struct rendition **renditions;

    int cur_seq_no;
    int live_start_index;
    int first_packet;
    int64_t first_timestamp;
    int64_t cur_timestamp;
    AVIOInterruptCB *interrupt_callback;
    char *user_agent;                    ///< holds HTTP user agent set as an AVOption to the HTTP protocol context
    char *cookies;                       ///< holds HTTP cookie values set in either the initial response or as an AVOption to the HTTP protocol context
    char *headers;                       ///< holds HTTP headers set as an AVOption to the HTTP protocol context
    char *http_proxy;                    ///< holds the address of the HTTP proxy server
    AVDictionary *avio_opts;
    int strict_std_compliance;
} HLSContext;

static int read_chomp_line(AVIOContext *s, char *buf, int maxlen)
{
    int len = ff_get_line(s, buf, maxlen);
    while (len > 0 && av_isspace(buf[len - 1]))
        buf[--len] = '\0';
    return len;
}

static void free_segment_list(struct playlist *pls)
{
    int i;
    for (i = 0; i < pls->n_segments; i++) {
        av_freep(&pls->segments[i]->key);
        av_freep(&pls->segments[i]->url);
        av_freep(&pls->segments[i]);
    }
    av_freep(&pls->segments);
    pls->n_segments = 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -204,6 +204,7 @@
     char *http_proxy;                    ///< holds the address of the HTTP proxy server
     AVDictionary *avio_opts;
     int strict_std_compliance;
+    char *allowed_extensions;
 } HLSContext;
 
 static int read_chomp_line(AVIOContext *s, char *buf, int maxlen)
@@ -618,8 +619,19 @@
         return AVERROR_INVALIDDATA;
 
     // only http(s) & file are allowed
-    if (!av_strstart(proto_name, "http", NULL) && !av_strstart(proto_name, "file", NULL))
+    if (av_strstart(proto_name, "file", NULL)) {
+        if (strcmp(c->allowed_extensions, "ALL") && !av_match_ext(url, c->allowed_extensions)) {
+            av_log(s, AV_LOG_ERROR,
+                "Filename extension of \'%s\' is not a common multimedia extension, blocked for security reasons.\n"
+                "If you wish to override this adjust allowed_extensions, you can set it to \'ALL\' to allow all\n",
+                url);
+            return AVERROR_INVALIDDATA;
+        }
+    } else if (av_strstart(proto_name, "http", NULL)) {
+        ;
+    } else
         return AVERROR_INVALIDDATA;
+
     if (!strncmp(proto_name, url, strlen(proto_name)) && url[strlen(proto_name)] == ':')
         ;
     else if (av_strstart(url, "crypto", NULL) && !strncmp(proto_name, url + 7, strlen(proto_name)) && url[7 + strlen(proto_name)] == ':')
@@ -2134,6 +2146,10 @@
 static const AVOption hls_options[] = {
     {"live_start_index", "segment index to start live streams at (negative values are from the end)",
         OFFSET(live_start_index), AV_OPT_TYPE_INT, {.i64 = -3}, INT_MIN, INT_MAX, FLAGS},
+    {"allowed_extensions", "List of file extensions that hls is allowed to access",
+        OFFSET(allowed_extensions), AV_OPT_TYPE_STRING,
+        {.str = "3gp,aac,avi,flac,mkv,m3u8,m4a,m4s,m4v,mpg,mov,mp2,mp3,mp4,mpeg,mpegts,ogg,ogv,oga,ts,vob,wav"},
+        INT_MIN, INT_MAX, FLAGS},
     {NULL}
 };
 
```
