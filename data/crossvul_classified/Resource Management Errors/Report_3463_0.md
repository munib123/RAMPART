# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3463_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3463_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 225-265 of the vulnerable file.


        if (ape->formatflags & MAC_FORMAT_FLAG_8_BIT)
            ape->bps = 8;
        else if (ape->formatflags & MAC_FORMAT_FLAG_24_BIT)
            ape->bps = 24;
        else
            ape->bps = 16;

        if (ape->fileversion >= 3950)
            ape->blocksperframe = 73728 * 4;
        else if (ape->fileversion >= 3900 || (ape->fileversion >= 3800  && ape->compressiontype >= 4000))
            ape->blocksperframe = 73728;
        else
            ape->blocksperframe = 9216;

        /* Skip any stored wav header */
        if (!(ape->formatflags & MAC_FORMAT_FLAG_CREATE_WAV_HEADER))
            avio_seek(pb, ape->wavheaderlength, SEEK_CUR);
    }

    if(ape->totalframes > UINT_MAX / sizeof(APEFrame)){
        av_log(s, AV_LOG_ERROR, "Too many frames: %d\n", ape->totalframes);
        return -1;
    }
    ape->frames       = av_malloc(ape->totalframes * sizeof(APEFrame));
    if(!ape->frames)
        return AVERROR(ENOMEM);
    ape->firstframe   = ape->junklength + ape->descriptorlength + ape->headerlength + ape->seektablelength + ape->wavheaderlength;
    ape->currentframe = 0;


    ape->totalsamples = ape->finalframeblocks;
    if (ape->totalframes > 1)
        ape->totalsamples += ape->blocksperframe * (ape->totalframes - 1);

    if (ape->seektablelength > 0) {
        ape->seektable = av_malloc(ape->seektablelength);
        for (i = 0; i < ape->seektablelength / sizeof(uint32_t); i++)
            ape->seektable[i] = avio_rl32(pb);
    }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -242,6 +242,10 @@
             avio_seek(pb, ape->wavheaderlength, SEEK_CUR);
     }
 
+    if(!ape->totalframes){
+        av_log(s, AV_LOG_ERROR, "No frames in the file!\n");
+        return AVERROR(EINVAL);
+    }
     if(ape->totalframes > UINT_MAX / sizeof(APEFrame)){
         av_log(s, AV_LOG_ERROR, "Too many frames: %d\n", ape->totalframes);
         return -1;
```
