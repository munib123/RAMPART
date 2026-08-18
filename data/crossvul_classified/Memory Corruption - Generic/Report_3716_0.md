# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3716_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3716_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 116-156 of the vulnerable file.

/* --------------- URL CHECK --------------------------- */

#define MAX_URL_SIZE  8192
#define MAX_METHOD_SIZE  16
#define SMALL_BUFF 1024

struct http_info {
    char method[MAX_METHOD_SIZE];
    char url[MAX_URL_SIZE];
};

int extract_http_info(ci_request_t *, ci_headers_list_t *, struct http_info *);
char *http_content_type(ci_request_t *);
void free_global ();
void free_pipe ();
void generate_redirect_page(char *, ci_request_t *, av_req_data_t *);
void cfgreload_command(char *, int, char **);
int create_pipe(char *command);
int dconnect (void);
int connectINET(char *serverHost, uint16_t serverPort);


/* ----------------------------------------------------- */


int squidclamav_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf)
{
    unsigned int xops;

    ci_debug_printf(1, "DEBUG squidclamav_init_service: Going to initialize squidclamav\n");

    squidclamav_xdata = srv_xdata;
    set_istag(squidclamav_xdata);
    ci_service_set_preview(srv_xdata, 1024);
    ci_service_enable_204(srv_xdata);
    ci_service_set_transfer_preview(srv_xdata, "*");

    xops = CI_XCLIENTIP | CI_XSERVERIP;
    xops |= CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS;
    ci_service_set_xopts(srv_xdata, xops);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -133,7 +133,7 @@
 int create_pipe(char *command);
 int dconnect (void);
 int connectINET(char *serverHost, uint16_t serverPort);
-
+char * replace(const char *s, const char *old, const char *new);
 
 /* ----------------------------------------------------- */
 
@@ -365,10 +365,14 @@
      
      /* Check URL header against squidGuard */
      if (usepipe == 1) {
+	char *rbuff = NULL;
 	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: Sending request to chained program: %s\n", squidguard);
 	ci_debug_printf(2, "DEBUG squidclamav_check_preview_handler: Request: %s %s %s %s\n", httpinf.url,clientip,username,httpinf.method);
-	fprintf(sgfpw,"%s %s %s %s\n",httpinf.url,clientip,username,httpinf.method);
+	/* escaping escaped character to prevent unescaping by squidguard */
+	rbuff = replace(httpinf.url, "%", "%25");
+	fprintf(sgfpw,"%s %s %s %s\n",rbuff,clientip,username,httpinf.method);
 	fflush(sgfpw);
+	xfree(rbuff);
 	/* the chained redirector must return empty line if ok or the redirection url */
 	chain_ret = (char *)malloc(sizeof(char)*MAX_URL_SIZE);
 	if (chain_ret != NULL) {
@@ -1628,3 +1632,40 @@
         return asockd;
 }
 
+
+/**
+ * Searches all occurrences of old into s
+ * and replaces with new
+ */
+char *
+replace(const char *s, const char *old, const char *new)
+{
+	char *ret;
+	int i, count = 0;
+	size_t newlen = strlen(new);
+	size_t oldlen = strlen(old);
+
+	for (i = 0; s[i] != '\0'; i++) {
+		if (strstr(&s[i], old) == &s[i]) {
+			count++;
+			i += oldlen - 1;
+		}
+	}
+	ret = malloc(i + 1 + count * (newlen - oldlen));
+	if (ret != NULL) {
+		i = 0;
+		while (*s) {
+			if (strstr(s, old) == s) {
+				strcpy(&ret[i], new);
+				i += newlen;
+				s += oldlen;
+			} else {
+				ret[i++] = *s++;
+			}
+		}
+		ret[i] = '\0';
+	}
+
+	return ret;
+}
+
```
