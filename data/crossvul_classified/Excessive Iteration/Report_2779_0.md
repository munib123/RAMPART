# CrossVul Fix Pair: Excessive Iteration in c
**Pair ID:** 2779_0
**Vulnerability Class:** Excessive Iteration
**CWE:** CWE-834
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2779_0`)

## Vulnerability Information & PoC

## Description
Excessive Iteration - If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 882-922 of the vulnerable file.

        break;
    case 0x4701:
        avio_read(pb, package->descriptor_ref, 16);
        break;
    case 0x4402:
        return mxf_read_utf16be_string(pb, size, &package->name);
    case 0x4406:
        return mxf_read_strong_ref_array(pb, &package->comment_refs,
                                             &package->comment_count);
    }
    return 0;
}

static int mxf_read_index_entry_array(AVIOContext *pb, MXFIndexTableSegment *segment)
{
    int i, length;

    segment->nb_index_entries = avio_rb32(pb);

    length = avio_rb32(pb);

    if (!(segment->temporal_offset_entries=av_calloc(segment->nb_index_entries, sizeof(*segment->temporal_offset_entries))) ||
        !(segment->flag_entries          = av_calloc(segment->nb_index_entries, sizeof(*segment->flag_entries))) ||
        !(segment->stream_offset_entries = av_calloc(segment->nb_index_entries, sizeof(*segment->stream_offset_entries)))) {
        av_freep(&segment->temporal_offset_entries);
        av_freep(&segment->flag_entries);
        return AVERROR(ENOMEM);
    }

    for (i = 0; i < segment->nb_index_entries; i++) {
        segment->temporal_offset_entries[i] = avio_r8(pb);
        avio_r8(pb);                                        /* KeyFrameOffset */
        segment->flag_entries[i] = avio_r8(pb);
        segment->stream_offset_entries[i] = avio_rb64(pb);
        avio_skip(pb, length - 11);
    }
    return 0;
}

static int mxf_read_index_table_segment(void *arg, AVIOContext *pb, int tag, int size, UID uid, int64_t klv_offset)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -899,6 +899,8 @@
     segment->nb_index_entries = avio_rb32(pb);
 
     length = avio_rb32(pb);
+    if(segment->nb_index_entries && length < 11)
+        return AVERROR_INVALIDDATA;
 
     if (!(segment->temporal_offset_entries=av_calloc(segment->nb_index_entries, sizeof(*segment->temporal_offset_entries))) ||
         !(segment->flag_entries          = av_calloc(segment->nb_index_entries, sizeof(*segment->flag_entries))) ||
@@ -909,6 +911,8 @@
     }
 
     for (i = 0; i < segment->nb_index_entries; i++) {
+        if(avio_feof(pb))
+            return AVERROR_INVALIDDATA;
         segment->temporal_offset_entries[i] = avio_r8(pb);
         avio_r8(pb);                                        /* KeyFrameOffset */
         segment->flag_entries[i] = avio_r8(pb);
```
