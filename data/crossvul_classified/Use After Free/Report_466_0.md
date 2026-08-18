# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 466_0
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `466_0`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 505-545 of the vulnerable file.

        AVStream *st2;
        if (i > 0) {
            st2 = avformat_new_stream(s, NULL);
            if (!st2) {
                ret = AVERROR(ENOMEM);
                return ret;
            }
            st2->id = st->id + (i<<16);
            st2->codecpar->bit_rate = st->codecpar->bit_rate;
            st2->start_time = st->start_time;
            st2->duration   = st->duration;
            st2->codecpar->codec_type = AVMEDIA_TYPE_DATA;
            st2->priv_data = ff_rm_alloc_rmstream();
            if (!st2->priv_data)
                return AVERROR(ENOMEM);
        } else
            st2 = st;

        size2 = avio_rb32(pb);
        ret = ff_rm_read_mdpr_codecdata(s, s->pb, st2, st2->priv_data,
                                        size2, mime);
        if (ret < 0)
            return ret;
    }
    return 0;
}

static int rm_read_header(AVFormatContext *s)
{
    RMDemuxContext *rm = s->priv_data;
    AVStream *st;
    AVIOContext *pb = s->pb;
    unsigned int tag;
    int tag_size;
    unsigned int start_time, duration;
    unsigned int data_off = 0, indx_off = 0;
    char buf[128], mime[128];
    int flags = 0;
    int ret = -1;
    unsigned size, v;
    int64_t codec_pos;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -522,7 +522,7 @@
 
         size2 = avio_rb32(pb);
         ret = ff_rm_read_mdpr_codecdata(s, s->pb, st2, st2->priv_data,
-                                        size2, mime);
+                                        size2, NULL);
         if (ret < 0)
             return ret;
     }
```
