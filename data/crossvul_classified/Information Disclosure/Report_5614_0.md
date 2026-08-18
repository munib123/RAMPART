# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 5614_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5614_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 101-141 of the vulnerable file.

static void freecookie(struct Cookie *co)
{
  if(co->expirestr)
    free(co->expirestr);
  if(co->domain)
    free(co->domain);
  if(co->path)
    free(co->path);
  if(co->name)
    free(co->name);
  if(co->value)
    free(co->value);
  if(co->maxage)
    free(co->maxage);
  if(co->version)
    free(co->version);

  free(co);
}

static bool tailmatch(const char *little, const char *bigone)
{
  size_t littlelen = strlen(little);
  size_t biglen = strlen(bigone);

  if(littlelen > biglen)
    return FALSE;

  return Curl_raw_equal(little, bigone+biglen-littlelen) ? TRUE : FALSE;
}

/*
 * Load cookies from all given cookie files (CURLOPT_COOKIEFILE).
 */
void Curl_cookie_loadfiles(struct SessionHandle *data)
{
  struct curl_slist *list = data->change.cookielist;
  if(list) {
    Curl_share_lock(data, CURL_LOCK_DATA_COOKIE, CURL_LOCK_ACCESS_SINGLE);
    while(list) {
      data->cookies = Curl_cookie_init(data,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,15 +118,29 @@
   free(co);
 }
 
-static bool tailmatch(const char *little, const char *bigone)
-{
-  size_t littlelen = strlen(little);
-  size_t biglen = strlen(bigone);
-
-  if(littlelen > biglen)
+static bool tailmatch(const char *cooke_domain, const char *hostname)
+{
+  size_t cookie_domain_len = strlen(cooke_domain);
+  size_t hostname_len = strlen(hostname);
+
+  if(hostname_len < cookie_domain_len)
     return FALSE;
 
-  return Curl_raw_equal(little, bigone+biglen-littlelen) ? TRUE : FALSE;
+  if(!Curl_raw_equal(cooke_domain, hostname+hostname_len-cookie_domain_len))
+    return FALSE;
+
+  /* A lead char of cookie_domain is not '.'.
+     RFC6265 4.1.2.3. The Domain Attribute says:
+       For example, if the value of the Domain attribute is
+       "example.com", the user agent will include the cookie in the Cookie
+       header when making HTTP requests to example.com, www.example.com, and
+       www.corp.example.com.
+   */
+  if(hostname_len == cookie_domain_len)
+    return TRUE;
+  if('.' == *(hostname + hostname_len - cookie_domain_len - 1))
+    return TRUE;
+  return FALSE;
 }
 
 /*
```
