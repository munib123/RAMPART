# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2763_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2763_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 153-193 of the vulnerable file.

            st->codecpar->bits_per_coded_sample;
        st->codecpar->block_align = st->codecpar->channels *
            st->codecpar->bits_per_coded_sample / 8;
        avpriv_set_pts_info(st,32,1,rate);
    }

    avpriv_set_pts_info(s->streams[0], 32, pts_num, pts_den);

    chunk_size =   av_malloc(frame_count * sizeof(uint32_t));
    audio_size =   av_malloc(frame_count * sizeof(uint32_t));
    chunk_offset = av_malloc(frame_count * sizeof(uint32_t));

    if(!chunk_size || !audio_size || !chunk_offset){
        av_free(chunk_size);
        av_free(audio_size);
        av_free(chunk_offset);
        return AVERROR(ENOMEM);
    }

    /** read offset and size tables */
    for(i=0; i < frame_count;i++)
        chunk_size[i] = avio_rl32(pb);
    for(i=0; i < frame_count;i++)
        chunk_offset[i] = avio_rl32(pb);
    for(i=0; i < frame_count;i++)
        audio_size[i] = avio_rl32(pb) & 0xFFFF;

    /** build the sample index */
    for(i=0;i<frame_count;i++){
        if(chunk_size[i] < 0 || audio_size[i] > chunk_size[i]){
            ret = AVERROR_INVALIDDATA;
            break;
        }

        if(sound_rate && audio_size[i]){
            av_add_index_entry(s->streams[1], chunk_offset[i],
                audio_frame_counter,audio_size[i], 0, AVINDEX_KEYFRAME);
            audio_frame_counter += audio_size[i] / channels;
        }
        av_add_index_entry(s->streams[0], chunk_offset[i] + audio_size[i],
            video_frame_counter,chunk_size[i]-audio_size[i],0,AVINDEX_KEYFRAME);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -170,12 +170,21 @@
     }
 
     /** read offset and size tables */
-    for(i=0; i < frame_count;i++)
+    for(i=0; i < frame_count;i++) {
+        if (avio_feof(pb))
+            return AVERROR_INVALIDDATA;
         chunk_size[i] = avio_rl32(pb);
-    for(i=0; i < frame_count;i++)
+    }
+    for(i=0; i < frame_count;i++) {
+        if (avio_feof(pb))
+            return AVERROR_INVALIDDATA;
         chunk_offset[i] = avio_rl32(pb);
-    for(i=0; i < frame_count;i++)
+    }
+    for(i=0; i < frame_count;i++) {
+        if (avio_feof(pb))
+            return AVERROR_INVALIDDATA;
         audio_size[i] = avio_rl32(pb) & 0xFFFF;
+    }
 
     /** build the sample index */
     for(i=0;i<frame_count;i++){
```
