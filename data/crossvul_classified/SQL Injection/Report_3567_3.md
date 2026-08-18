# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in c
**Pair ID:** 3567_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3567_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```c
Lines 897-941 of the vulnerable file.

  Curl_pp_disconnect(&pop3c->pp);

  return CURLE_OK;
}

/***********************************************************************
 *
 * pop3_parse_url_path()
 *
 * Parse the URL path into separate path components.
 *
 */
static CURLcode pop3_parse_url_path(struct connectdata *conn)
{
  /* the pop3 struct is already inited in pop3_connect() */
  struct pop3_conn *pop3c = &conn->proto.pop3c;
  struct SessionHandle *data = conn->data;
  const char *path = data->state.path;

  /* url decode the path and use this mailbox */
  pop3c->mailbox = curl_easy_unescape(data, path, 0, NULL);
  if(!pop3c->mailbox)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

/* call this when the DO phase has completed */
static CURLcode pop3_dophase_done(struct connectdata *conn,
                                  bool connected)
{
  struct FTP *pop3 = conn->data->state.proto.pop3;
  (void)connected;

  if(pop3->transfer != FTPTRANSFER_BODY)
    /* no data to transfer */
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return CURLE_OK;
}

/* called from multi.c while DOing */
static CURLcode pop3_doing(struct connectdata *conn,
                               bool *dophase_done)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -914,11 +914,7 @@
   const char *path = data->state.path;
 
   /* url decode the path and use this mailbox */
-  pop3c->mailbox = curl_easy_unescape(data, path, 0, NULL);
-  if(!pop3c->mailbox)
-    return CURLE_OUT_OF_MEMORY;
-
-  return CURLE_OK;
+  return Curl_urldecode(data, path, 0, &pop3c->mailbox, NULL, TRUE);
 }
 
 /* call this when the DO phase has completed */
```
