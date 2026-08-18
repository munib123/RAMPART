# CrossVul Fix Pair: Double Free in c
**Pair ID:** 2938_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2938_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 1340-1380 of the vulnerable file.


    req = snmp_pdu_create(SNMP_MSG_GETNEXT);
    if (req == NULL) {
      ERROR("snmp plugin: snmp_pdu_create failed.");
      status = -1;
      break;
    }

    oid_list_todo_num = 0;
    for (i = 0; i < oid_list_len; i++) {
      /* Do not rerequest already finished OIDs */
      if (!oid_list_todo[i])
        continue;
      oid_list_todo_num++;
      snmp_add_null_var(req, oid_list[i].oid, oid_list[i].oid_len);
    }

    if (oid_list_todo_num == 0) {
      /* The request is still empty - so we are finished */
      DEBUG("snmp plugin: all variables have left their subtree");
      status = 0;
      break;
    }

    res = NULL;
    status = snmp_sess_synch_response(host->sess_handle, req, &res);
    if ((status != STAT_SUCCESS) || (res == NULL)) {
      char *errstr = NULL;

      snmp_sess_error(host->sess_handle, NULL, NULL, &errstr);

      c_complain(LOG_ERR, &host->complaint,
                 "snmp plugin: host %s: snmp_sess_synch_response failed: %s",
                 host->name, (errstr == NULL) ? "Unknown problem" : errstr);

      if (res != NULL)
        snmp_free_pdu(res);
      res = NULL;

      /* snmp_synch_response already freed our PDU */
      req = NULL;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1357,11 +1357,13 @@
     if (oid_list_todo_num == 0) {
       /* The request is still empty - so we are finished */
       DEBUG("snmp plugin: all variables have left their subtree");
+      snmp_free_pdu(req);
       status = 0;
       break;
     }
 
     res = NULL;
+    /* snmp_sess_synch_response always frees our req PDU */
     status = snmp_sess_synch_response(host->sess_handle, req, &res);
     if ((status != STAT_SUCCESS) || (res == NULL)) {
       char *errstr = NULL;
@@ -1376,8 +1378,6 @@
         snmp_free_pdu(res);
       res = NULL;
 
-      /* snmp_synch_response already freed our PDU */
-      req = NULL;
       sfree(errstr);
       csnmp_host_close_session(host);
 
@@ -1492,9 +1492,6 @@
     snmp_free_pdu(res);
   res = NULL;
 
-  if (req != NULL)
-    snmp_free_pdu(req);
-  req = NULL;
 
   if (status == 0)
     csnmp_dispatch_table(host, data, instance_list_head, value_list_head);
```
