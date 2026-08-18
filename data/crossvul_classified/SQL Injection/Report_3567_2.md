# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in c
**Pair ID:** 3567_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3567_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```c
Lines 936-976 of the vulnerable file.

  Curl_pp_disconnect(&imapc->pp);

  Curl_safefree(imapc->mailbox);

  return CURLE_OK;
}

/***********************************************************************
 *
 * imap_parse_url_path()
 *
 * Parse the URL path into separate path components.
 *
 */
static CURLcode imap_parse_url_path(struct connectdata *conn)
{
  /* the imap struct is already inited in imap_connect() */
  struct imap_conn *imapc = &conn->proto.imapc;
  struct SessionHandle *data = conn->data;
  const char *path = data->state.path;
  int len;

  if(!*path)
    path = "INBOX";

  /* url decode the path and use this mailbox */
  imapc->mailbox = curl_easy_unescape(data, path, 0, &len);
  if(!imapc->mailbox)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

/* call this when the DO phase has completed */
static CURLcode imap_dophase_done(struct connectdata *conn,
                                  bool connected)
{
  struct FTP *imap = conn->data->state.proto.imap;
  (void)connected;

  if(imap->transfer != FTPTRANSFER_BODY)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -953,17 +953,12 @@
   struct imap_conn *imapc = &conn->proto.imapc;
   struct SessionHandle *data = conn->data;
   const char *path = data->state.path;
-  int len;
 
   if(!*path)
     path = "INBOX";
 
   /* url decode the path and use this mailbox */
-  imapc->mailbox = curl_easy_unescape(data, path, 0, &len);
-  if(!imapc->mailbox)
-    return CURLE_OUT_OF_MEMORY;
-
-  return CURLE_OK;
+  return Curl_urldecode(data, path, 0, &imapc->mailbox, NULL, TRUE);
 }
 
 /* call this when the DO phase has completed */
```
