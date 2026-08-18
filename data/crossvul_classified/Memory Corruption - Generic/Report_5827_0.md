# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5827_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5827_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 220-260 of the vulnerable file.

                pc->overread, pc->state, next, pc->index, pc->overread_index);
        av_dlog(NULL, "%X %X %X %X\n", (*buf)[0], (*buf)[1], (*buf)[2], (*buf)[3]);
    }

    /* Copy overread bytes from last frame into buffer. */
    for(; pc->overread>0; pc->overread--){
        pc->buffer[pc->index++]= pc->buffer[pc->overread_index++];
    }

    /* flush remaining if EOF */
    if(!*buf_size && next == END_NOT_FOUND){
        next= 0;
    }

    pc->last_index= pc->index;

    /* copy into buffer end return */
    if(next == END_NOT_FOUND){
        void* new_buffer = av_fast_realloc(pc->buffer, &pc->buffer_size, (*buf_size) + pc->index + FF_INPUT_BUFFER_PADDING_SIZE);

        if(!new_buffer)
            return AVERROR(ENOMEM);
        pc->buffer = new_buffer;
        memcpy(&pc->buffer[pc->index], *buf, *buf_size);
        pc->index += *buf_size;
        return -1;
    }

    *buf_size=
    pc->overread_index= pc->index + next;

    /* append to buffer */
    if(pc->index){
        void* new_buffer = av_fast_realloc(pc->buffer, &pc->buffer_size, next + pc->index + FF_INPUT_BUFFER_PADDING_SIZE);

        if(!new_buffer)
            return AVERROR(ENOMEM);
        pc->buffer = new_buffer;
        if (next > -FF_INPUT_BUFFER_PADDING_SIZE)
            memcpy(&pc->buffer[pc->index], *buf,
                   next + FF_INPUT_BUFFER_PADDING_SIZE);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -237,8 +237,10 @@
     if(next == END_NOT_FOUND){
         void* new_buffer = av_fast_realloc(pc->buffer, &pc->buffer_size, (*buf_size) + pc->index + FF_INPUT_BUFFER_PADDING_SIZE);
 
-        if(!new_buffer)
+        if(!new_buffer) {
+            pc->index = 0;
             return AVERROR(ENOMEM);
+        }
         pc->buffer = new_buffer;
         memcpy(&pc->buffer[pc->index], *buf, *buf_size);
         pc->index += *buf_size;
@@ -251,9 +253,11 @@
     /* append to buffer */
     if(pc->index){
         void* new_buffer = av_fast_realloc(pc->buffer, &pc->buffer_size, next + pc->index + FF_INPUT_BUFFER_PADDING_SIZE);
-
-        if(!new_buffer)
+        if(!new_buffer) {
+            pc->overread_index =
+            pc->index = 0;
             return AVERROR(ENOMEM);
+        }
         pc->buffer = new_buffer;
         if (next > -FF_INPUT_BUFFER_PADDING_SIZE)
             memcpy(&pc->buffer[pc->index], *buf,
```
