# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5533_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5533_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 150-190 of the vulnerable file.

    robj *tail;
    if (listLength(c->reply) == 0) {
        listAddNodeTail(c->reply,createStringObject(s,len));
    } else {
        tail = listNodeValue(listLast(c->reply));

        /* Append to this object when possible. */
        if (tail->ptr != NULL &&
            sdslen(tail->ptr)+len <= REDIS_REPLY_CHUNK_BYTES)
        {
            tail = dupLastObjectIfNeeded(c->reply);
            tail->ptr = sdscatlen(tail->ptr,s,len);
        } else {
            listAddNodeTail(c->reply,createStringObject(s,len));
        }
    }
}

void addReply(redisClient *c, robj *obj) {
    if (_installWriteEvent(c) != REDIS_OK) return;
    redisAssert(!server.vm_enabled || obj->storage == REDIS_VM_MEMORY);

    /* This is an important place where we can avoid copy-on-write
     * when there is a saving child running, avoiding touching the
     * refcount field of the object if it's not needed.
     *
     * If the encoding is RAW and there is room in the static buffer
     * we'll be able to send the object to the client without
     * messing with its page. */
    if (obj->encoding == REDIS_ENCODING_RAW) {
        if (_addReplyToBuffer(c,obj->ptr,sdslen(obj->ptr)) != REDIS_OK)
            _addReplyObjectToList(c,obj);
    } else {
        /* FIXME: convert the long into string and use _addReplyToBuffer()
         * instead of calling getDecodedObject. As this place in the
         * code is too performance critical. */
        obj = getDecodedObject(obj);
        if (_addReplyToBuffer(c,obj->ptr,sdslen(obj->ptr)) != REDIS_OK)
            _addReplyObjectToList(c,obj);
        decrRefCount(obj);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -167,7 +167,7 @@
 
 void addReply(redisClient *c, robj *obj) {
     if (_installWriteEvent(c) != REDIS_OK) return;
-    redisAssert(!server.vm_enabled || obj->storage == REDIS_VM_MEMORY);
+    redisAssert(!server.ds_enabled || obj->storage == REDIS_VM_MEMORY);
 
     /* This is an important place where we can avoid copy-on-write
      * when there is a saving child running, avoiding touching the
@@ -460,7 +460,7 @@
     /* Remove from the list of clients waiting for swapped keys, or ready
      * to be restarted, but not yet woken up again. */
     if (c->flags & REDIS_IO_WAIT) {
-        redisAssert(server.vm_enabled);
+        redisAssert(server.ds_enabled);
         if (listLength(c->io_keys) == 0) {
             ln = listSearchKey(server.io_ready_clients,c);
 
@@ -474,7 +474,7 @@
                 dontWaitForSwappedKey(c,ln->value);
             }
         }
-        server.vm_blocked_clients--;
+        server.cache_blocked_clients--;
     }
     listRelease(c->io_keys);
     /* Master/slave cleanup.
```
