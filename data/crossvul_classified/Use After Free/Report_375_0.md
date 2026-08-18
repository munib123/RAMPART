# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 375_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `375_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 314-354 of the vulnerable file.

 * NOTE: if we ever add something that attempts to write to a socket or
 * similar here, we must ignore SIGPIPE first. It is currently only done
 * when curl_easy_perform() is invoked.
 */

CURLcode Curl_close(struct Curl_easy *data)
{
  struct Curl_multi *m;

  if(!data)
    return CURLE_OK;

  Curl_expire_clear(data); /* shut off timers */

  m = data->multi;
  if(m)
    /* This handle is still part of a multi handle, take care of this first
       and detach this handle from there. */
    curl_multi_remove_handle(data->multi, data);

  if(data->multi_easy)
    /* when curl_easy_perform() is used, it creates its own multi handle to
       use and this is the one */
    curl_multi_cleanup(data->multi_easy);

  /* Destroy the timeout list that is held in the easy handle. It is
     /normally/ done by curl_multi_remove_handle() but this is "just in
     case" */
  Curl_llist_destroy(&data->state.timeoutlist, NULL);

  data->magic = 0; /* force a clear AFTER the possibly enforced removal from
                      the multi handle, since that function uses the magic
                      field! */

  if(data->state.rangestringalloc)
    free(data->state.range);

  /* freed here just in case DONE wasn't called */
  Curl_free_request_state(data);

  /* Close down all open SSL info and sessions */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -331,10 +331,12 @@
        and detach this handle from there. */
     curl_multi_remove_handle(data->multi, data);
 
-  if(data->multi_easy)
+  if(data->multi_easy) {
     /* when curl_easy_perform() is used, it creates its own multi handle to
        use and this is the one */
     curl_multi_cleanup(data->multi_easy);
+    data->multi_easy = NULL;
+  }
 
   /* Destroy the timeout list that is held in the easy handle. It is
      /normally/ done by curl_multi_remove_handle() but this is "just in
```
