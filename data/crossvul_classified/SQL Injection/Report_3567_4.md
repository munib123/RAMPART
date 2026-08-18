# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in c
**Pair ID:** 3567_4
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3567_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```c
Lines 1227-1267 of the vulnerable file.


  return CURLE_OK;
}

/*
 * smtp_connect() should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable pointed to by 'done' will be TRUE if the protocol-layer
 * connect phase is done when this function returns, or FALSE if not. When
 * called as a part of the easy interface, it will always be TRUE.
 */
static CURLcode smtp_connect(struct connectdata *conn,
                             bool *done) /* see description above */
{
  CURLcode result;
  struct smtp_conn *smtpc = &conn->proto.smtpc;
  struct SessionHandle *data = conn->data;
  struct pingpong *pp = &smtpc->pp;
  const char *path = conn->data->state.path;
  int len;
  char localhost[HOSTNAME_MAX + 1];

  *done = FALSE; /* default to not done yet */

  /* If there already is a protocol-specific struct allocated for this
     sessionhandle, deal with it */
  Curl_reset_reqproto(conn);

  result = smtp_init(conn);
  if(CURLE_OK != result)
    return result;

  /* We always support persistent connections on smtp */
  conn->bits.close = FALSE;

  pp->response_time = RESP_TIMEOUT; /* set default response time-out */
  pp->statemach_act = smtp_statemach_act;
  pp->endofresp = smtp_endofresp;
  pp->conn = conn;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1244,7 +1244,6 @@
   struct SessionHandle *data = conn->data;
   struct pingpong *pp = &smtpc->pp;
   const char *path = conn->data->state.path;
-  int len;
   char localhost[HOSTNAME_MAX + 1];
 
   *done = FALSE; /* default to not done yet */
@@ -1316,9 +1315,9 @@
   }
 
   /* url decode the path and use it as domain with EHLO */
-  smtpc->domain = curl_easy_unescape(conn->data, path, 0, &len);
-  if(!smtpc->domain)
-    return CURLE_OUT_OF_MEMORY;
+  result = Curl_urldecode(conn->data, path, 0, &smtpc->domain, NULL, TRUE);
+  if(result)
+    return result;
 
   /* When we connect, we start in the state where we await the server greeting
    */
```
