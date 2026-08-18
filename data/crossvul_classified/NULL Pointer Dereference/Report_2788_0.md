# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2788_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2788_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1908-1948 of the vulnerable file.

                print_q("blue_y", metadata->display_primaries[2][1], '/');

                print_q("white_point_x", metadata->white_point[0], '/');
                print_q("white_point_y", metadata->white_point[1], '/');
            }

            if (metadata->has_luminance) {
                print_q("min_luminance", metadata->min_luminance, '/');
                print_q("max_luminance", metadata->max_luminance, '/');
            }
        } else if (sd->type == AV_PKT_DATA_CONTENT_LIGHT_LEVEL) {
            AVContentLightMetadata *metadata = (AVContentLightMetadata *)sd->data;
            print_int("max_content", metadata->MaxCLL);
            print_int("max_average", metadata->MaxFALL);
        }
        writer_print_section_footer(w);
    }
    writer_print_section_footer(w);
}

static void clear_log(int need_lock)
{
    int i;

    if (need_lock)
        pthread_mutex_lock(&log_mutex);
    for (i=0; i<log_buffer_size; i++) {
        av_freep(&log_buffer[i].context_name);
        av_freep(&log_buffer[i].parent_name);
        av_freep(&log_buffer[i].log_message);
    }
    log_buffer_size = 0;
    if(need_lock)
        pthread_mutex_unlock(&log_mutex);
}

static int show_log(WriterContext *w, int section_ids, int section_id, int log_level)
{
    int i;
    pthread_mutex_lock(&log_mutex);
    if (!log_buffer_size) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1925,6 +1925,16 @@
     writer_print_section_footer(w);
 }
 
+static void print_primaries(WriterContext *w, enum AVColorPrimaries color_primaries)
+{
+    const char *val = av_color_primaries_name(color_primaries);
+    if (!val || color_primaries == AVCOL_PRI_UNSPECIFIED) {
+        print_str_opt("color_primaries", "unknown");
+    } else {
+        print_str("color_primaries", val);
+    }
+}
+
 static void clear_log(int need_lock)
 {
     int i;
@@ -2116,10 +2126,7 @@
         else
             print_str_opt("color_space", av_color_space_name(frame->colorspace));
 
-        if (frame->color_primaries != AVCOL_PRI_UNSPECIFIED)
-            print_str("color_primaries", av_color_primaries_name(frame->color_primaries));
-        else
-            print_str_opt("color_primaries", av_color_primaries_name(frame->color_primaries));
+        print_primaries(w, frame->color_primaries);
 
         if (frame->color_trc != AVCOL_TRC_UNSPECIFIED)
             print_str("color_transfer", av_color_transfer_name(frame->color_trc));
@@ -2516,10 +2523,7 @@
         else
             print_str_opt("color_transfer", av_color_transfer_name(par->color_trc));
 
-        if (par->color_primaries != AVCOL_PRI_UNSPECIFIED)
-            print_str("color_primaries", av_color_primaries_name(par->color_primaries));
-        else
-            print_str_opt("color_primaries", av_color_primaries_name(par->color_primaries));
+        print_primaries(w, par->color_primaries);
 
         if (par->chroma_location != AVCHROMA_LOC_UNSPECIFIED)
             print_str("chroma_location", av_chroma_location_name(par->chroma_location));
```
