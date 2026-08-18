# CrossVul Fix Pair: Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) in cpp
**Pair ID:** 194_0
**Vulnerability Class:** Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)
**CWE:** CWE-335
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `194_0`)

## Vulnerability Information & PoC

## Description
Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) - PRNGs are deterministic and, while their output appears random, they cannot actually create entropy.

## Vulnerable Code
```cpp
Lines 847-887 of the vulnerable file.

  }
}

/* ****************************************** */

static int handle_http_message(const struct mg_connection *conn, const char *message) {
  ntop->getTrace()->traceEvent(TRACE_ERROR, "[HTTP] %s", message);
  return 1;
}

HTTPserver::HTTPserver(const char *_docs_dir, const char *_scripts_dir) {
  struct mg_callbacks callbacks;
  static char ports[256], ssl_cert_path[MAX_PATH] = { 0 }, access_log_path[MAX_PATH] = { 0 };
  const char *http_binding_addr = ntop->getPrefs()->get_http_binding_address();
  const char *https_binding_addr = ntop->getPrefs()->get_https_binding_address();
  char tmpBuf[8];
  bool use_ssl = false;
  bool use_http = true;
  struct stat statsBuf;
  int stat_rc;

  static char *http_options[] = {
    (char*)"listening_ports", ports,
    (char*)"enable_directory_listing", (char*)"no",
    (char*)"document_root",  (char*)_docs_dir,
    /* (char*)"extra_mime_types", (char*)"" */ /* see mongoose.c */
    (char*)"num_threads", (char*)"5",
    NULL, NULL, NULL, NULL,
    NULL
  };

  docs_dir = strdup(_docs_dir), scripts_dir = strdup(_scripts_dir);
  httpserver = this;
  if(ntop->getPrefs()->get_http_port() == 0) use_http = false;

  if(use_http) {
    snprintf(ports, sizeof(ports), "%s%s%d",
	     http_binding_addr,
	     (http_binding_addr[0] == '\0') ? "" : ":",
	     ntop->getPrefs()->get_http_port());
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -864,7 +864,12 @@
   bool use_http = true;
   struct stat statsBuf;
   int stat_rc;
-
+  struct timeval tv;
+
+  /* Randomize data */
+  gettimeofday(&tv, NULL);
+  srand(tv.tv_sec + tv.tv_usec);
+  
   static char *http_options[] = {
     (char*)"listening_ports", ports,
     (char*)"enable_directory_listing", (char*)"no",
```
