# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2765_1
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2765_1`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 188-228 of the vulnerable file.

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
    char *allowed_extensions;
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
@@ -205,6 +205,7 @@
     AVDictionary *avio_opts;
     int strict_std_compliance;
     char *allowed_extensions;
+    int max_reload;
 } HLSContext;
 
 static int read_chomp_line(AVIOContext *s, char *buf, int maxlen)
@@ -1263,6 +1264,7 @@
     HLSContext *c = v->parent->priv_data;
     int ret, i;
     int just_opened = 0;
+    int reload_count = 0;
 
 restart:
     if (!v->needed)
@@ -1294,6 +1296,9 @@
         reload_interval = default_reload_interval(v);
 
 reload:
+        reload_count++;
+        if (reload_count > c->max_reload)
+            return AVERROR_EOF;
         if (!v->finished &&
             av_gettime_relative() - v->last_load_time >= reload_interval) {
             if ((ret = parse_playlist(c, v->url, v, NULL)) < 0) {
@@ -2150,6 +2155,8 @@
         OFFSET(allowed_extensions), AV_OPT_TYPE_STRING,
         {.str = "3gp,aac,avi,flac,mkv,m3u8,m4a,m4s,m4v,mpg,mov,mp2,mp3,mp4,mpeg,mpegts,ogg,ogv,oga,ts,vob,wav"},
         INT_MIN, INT_MAX, FLAGS},
+    {"max_reload", "Maximum number of times a insufficient list is attempted to be reloaded",
+        OFFSET(max_reload), AV_OPT_TYPE_INT, {.i64 = 1000}, 0, INT_MAX, FLAGS},
     {NULL}
 };
 
```
