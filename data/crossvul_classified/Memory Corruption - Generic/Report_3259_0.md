# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3259_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3259_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 96-136 of the vulnerable file.

  {"proxy_ssl_verify_result", VAR_PROXY_SSL_VERIFY_RESULT},
  {"filename_effective", VAR_EFFECTIVE_FILENAME},
  {"remote_ip", VAR_PRIMARY_IP},
  {"remote_port", VAR_PRIMARY_PORT},
  {"local_ip", VAR_LOCAL_IP},
  {"local_port", VAR_LOCAL_PORT},
  {"http_version", VAR_HTTP_VERSION},
  {"scheme", VAR_SCHEME},
  {NULL, VAR_NONE}
};

void ourWriteOut(CURL *curl, struct OutStruct *outs, const char *writeinfo)
{
  FILE *stream = stdout;
  const char *ptr = writeinfo;
  char *stringp = NULL;
  long longinfo;
  double doubleinfo;

  while(ptr && *ptr) {
    if('%' == *ptr) {
      if('%' == ptr[1]) {
        /* an escaped %-letter */
        fputc('%', stream);
        ptr += 2;
      }
      else {
        /* this is meant as a variable to output */
        char *end;
        char keepit;
        int i;
        if('{' == ptr[1]) {
          bool match = FALSE;
          end = strchr(ptr, '}');
          ptr += 2; /* pass the % and the { */
          if(!end) {
            fputs("%{", stream);
            continue;
          }
          keepit = *end;
          *end = 0; /* zero terminate */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -113,7 +113,7 @@
   double doubleinfo;
 
   while(ptr && *ptr) {
-    if('%' == *ptr) {
+    if('%' == *ptr && ptr[1]) {
       if('%' == ptr[1]) {
         /* an escaped %-letter */
         fputc('%', stream);
```
