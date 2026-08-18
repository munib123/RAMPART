# CrossVul Fix Pair: Use of Externally-Controlled Format String in c
**Pair ID:** 2610_0
**Vulnerability Class:** Use of Externally-Controlled Format String
**CWE:** CWE-134
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2610_0`)

## Vulnerability Information & PoC

## Description
Use of Externally-Controlled Format String - When an attacker can modify an externally-controlled format string, this can lead to buffer overflows, denial of service, or data representation problems.

## Vulnerable Code
```c
Lines 386-426 of the vulnerable file.

    if (info->rcvTimeout > -1)      zsocket_set_rcvtimeo(*sock, info->rcvTimeout);
    if (info->maxMsgSize > -1)      zsocket_set_maxmsgsize(*sock, info->maxMsgSize);
    if (info->rate > -1)            zsocket_set_rate(*sock, info->rate);
    if (info->recoveryIVL > -1)     zsocket_set_recovery_ivl(*sock, info->recoveryIVL);
    if (info->multicastHops > -1)   zsocket_set_multicast_hops(*sock, info->multicastHops);
    if (info->reconnectIVL > -1)    zsocket_set_reconnect_ivl(*sock, info->reconnectIVL);
    if (info->reconnectIVLMax > -1) zsocket_set_reconnect_ivl_max(*sock, info->reconnectIVLMax);
    if (info->ipv4Only > -1)        zsocket_set_ipv4only(*sock, info->ipv4Only);
    if (info->affinity > -1)        zsocket_set_affinity(*sock, info->affinity);
    if (info->sndHWM > -1 )         zsocket_set_sndhwm(*sock, info->sndHWM);
    if (info->rcvHWM > -1 )         zsocket_set_rcvhwm(*sock, info->rcvHWM);
    /* Set subscriptions.*/
    if (info->type == ZMQ_SUB) {
        for(sub = info->subscriptions; sub!=NULL; sub=sub->next) {
            zsocket_set_subscribe(*sock, sub->subscribe);
        }
    }

    /* Do the bind/connect... */
    if (info->action==ACTION_CONNECT) {
        rv = zsocket_connect(*sock, info->description);
        if (rv == -1) {
            errmsg.LogError(0,
                            RS_RET_INVALID_PARAMS,
                            "zmq_connect using %s failed: %s",
                            info->description, zmq_strerror(errno));
            return RS_RET_INVALID_PARAMS;
        }
        DBGPRINTF("imzmq3: connect for %s successful\n",info->description);
    } else {
        rv = zsocket_bind(*sock, info->description);
        if (rv == -1) {
            errmsg.LogError(0,
                            RS_RET_INVALID_PARAMS,
                            "zmq_bind using %s failed: %s",
                            info->description, zmq_strerror(errno));
            return RS_RET_INVALID_PARAMS;
        }
        DBGPRINTF("imzmq3: bind for %s successful\n",info->description);
    }
    return RS_RET_OK;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -403,7 +403,7 @@
 
     /* Do the bind/connect... */
     if (info->action==ACTION_CONNECT) {
-        rv = zsocket_connect(*sock, info->description);
+        rv = zsocket_connect(*sock, "%s", info->description);
         if (rv == -1) {
             errmsg.LogError(0,
                             RS_RET_INVALID_PARAMS,
@@ -413,7 +413,7 @@
         }
         DBGPRINTF("imzmq3: connect for %s successful\n",info->description);
     } else {
-        rv = zsocket_bind(*sock, info->description);
+        rv = zsocket_bind(*sock, "%s", info->description);
         if (rv == -1) {
             errmsg.LogError(0,
                             RS_RET_INVALID_PARAMS,
```
