# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 433_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `433_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 216-256 of the vulnerable file.

    return ret;
}

inline int web_client_api_request_v1_alarm_variables(RRDHOST *host, struct web_client *w, char *url) {
    return web_client_api_request_single_chart(host, w, url, health_api_v1_chart_variables2json);
}

inline int web_client_api_request_v1_charts(RRDHOST *host, struct web_client *w, char *url) {
    (void)url;

    buffer_flush(w->response.data);
    w->response.data->contenttype = CT_APPLICATION_JSON;
    charts2json(host, w->response.data);
    return 200;
}

inline int web_client_api_request_v1_chart(RRDHOST *host, struct web_client *w, char *url) {
    return web_client_api_request_single_chart(host, w, url, rrd_stats_api_v1_chart);
}

// returns the HTTP code
inline int web_client_api_request_v1_data(RRDHOST *host, struct web_client *w, char *url) {
    debug(D_WEB_CLIENT, "%llu: API v1 data with URL '%s'", w->id, url);

    int ret = 400;
    BUFFER *dimensions = NULL;

    buffer_flush(w->response.data);

    char    *google_version = "0.6",
            *google_reqId = "0",
            *google_sig = "0",
            *google_out = "json",
            *responseHandler = NULL,
            *outFileName = NULL;

    time_t last_timestamp_in_data = 0, google_timestamp = 0;

    char *chart = NULL
    , *before_str = NULL
    , *after_str = NULL
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -233,6 +233,15 @@
     return web_client_api_request_single_chart(host, w, url, rrd_stats_api_v1_chart);
 }
 
+void fix_google_param(char *s) {
+    if(unlikely(!s)) return;
+
+    for( ; *s ;s++) {
+        if(!isalnum(*s) && *s != '.' && *s != '_' && *s != '-')
+            *s = '_';
+    }
+}
+
 // returns the HTTP code
 inline int web_client_api_request_v1_data(RRDHOST *host, struct web_client *w, char *url) {
     debug(D_WEB_CLIENT, "%llu: API v1 data with URL '%s'", w->id, url);
@@ -332,6 +341,14 @@
         }
     }
 
+    // validate the google parameters given
+    fix_google_param(google_out);
+    fix_google_param(google_sig);
+    fix_google_param(google_reqId);
+    fix_google_param(google_version);
+    fix_google_param(responseHandler);
+    fix_google_param(outFileName);
+
     if(!chart || !*chart) {
         buffer_sprintf(w->response.data, "No chart id is given at the request.");
         goto cleanup;
```
