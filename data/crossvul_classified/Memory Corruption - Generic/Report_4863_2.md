# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4863_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4863_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 12-52 of the vulnerable file.

    if (!extra_length)
        return;

    memory_length    = qp->d_memory_end - qp->d_memory;

    q_length = 
        qp->d_read <= qp->d_write ?
            (size_t)(qp->d_write - qp->d_read)
        :
            memory_length - (qp->d_read - qp->d_write);

    available_length = memory_length - q_length - 1;
                            /* -1, as the Q cannot completely fill up all   */
                            /* available memory in the buffer               */

    if (message_show(MSG_INFO))
        message("push_front %u bytes in `%s'", (unsigned)extra_length, info);

    if (extra_length > available_length)
    {
                                                   /* enlarge the buffer:  */
        memory_length += extra_length - available_length + BLOCK_QUEUE;
        cp = new_memory(memory_length, sizeof(char));

        if (message_show(MSG_INFO))
            message("Reallocating queue at %p to %p", qp->d_memory, cp);

        if (qp->d_read > qp->d_write)               /* q wraps around end   */
        {
            size_t tail_len = qp->d_memory_end - qp->d_read;
            memcpy(cp, qp->d_read, tail_len);       /* first part -> begin  */
                                                    /* 2nd part beyond      */
            memcpy(cp + tail_len, qp->d_memory, 
                                    (size_t)(qp->d_write - qp->d_memory));
            qp->d_write = cp + q_length;
            qp->d_read = cp;
        }
        else                                        /* q as one block       */
        {
            memcpy(cp, qp->d_memory, memory_length);/* cp existing buffer   */
            qp->d_read = cp + (qp->d_read - qp->d_memory);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,8 +29,11 @@
 
     if (extra_length > available_length)
     {
+        size_t original_length = memory_length;
+
                                                    /* enlarge the buffer:  */
         memory_length += extra_length - available_length + BLOCK_QUEUE;
+
         cp = new_memory(memory_length, sizeof(char));
 
         if (message_show(MSG_INFO))
@@ -48,7 +51,7 @@
         }
         else                                        /* q as one block       */
         {
-            memcpy(cp, qp->d_memory, memory_length);/* cp existing buffer   */
+            memcpy(cp, qp->d_memory, original_length);/* cp existing buffer   */
             qp->d_read = cp + (qp->d_read - qp->d_memory);
             qp->d_write = cp + (qp->d_write - qp->d_memory);
         }
```
