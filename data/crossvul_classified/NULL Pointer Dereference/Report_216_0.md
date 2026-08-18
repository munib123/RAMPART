# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 216_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `216_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 1963-2003 of the vulnerable file.

    int hours, minutes, seconds;

    if (!show_bits(gb, 23)) {
        av_log(s->avctx, AV_LOG_WARNING, "GOP header invalid\n");
        return AVERROR_INVALIDDATA;
    }

    hours   = get_bits(gb, 5);
    minutes = get_bits(gb, 6);
    check_marker(s->avctx, gb, "in gop_header");
    seconds = get_bits(gb, 6);

    s->time_base = seconds + 60*(minutes + 60*hours);

    skip_bits1(gb);
    skip_bits1(gb);

    return 0;
}

static int mpeg4_decode_profile_level(MpegEncContext *s, GetBitContext *gb)
{

    s->avctx->profile = get_bits(gb, 4);
    s->avctx->level   = get_bits(gb, 4);

    // for Simple profile, level 0
    if (s->avctx->profile == 0 && s->avctx->level == 8) {
        s->avctx->level = 0;
    }

    return 0;
}

static int mpeg4_decode_visual_object(MpegEncContext *s, GetBitContext *gb)
{
    int visual_object_type;
    int is_visual_object_identifier = get_bits1(gb);

    if (is_visual_object_identifier) {
        skip_bits(gb, 4+3);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1980,15 +1980,15 @@
     return 0;
 }
 
-static int mpeg4_decode_profile_level(MpegEncContext *s, GetBitContext *gb)
-{
-
-    s->avctx->profile = get_bits(gb, 4);
-    s->avctx->level   = get_bits(gb, 4);
+static int mpeg4_decode_profile_level(MpegEncContext *s, GetBitContext *gb, int *profile, int *level)
+{
+
+    *profile = get_bits(gb, 4);
+    *level   = get_bits(gb, 4);
 
     // for Simple profile, level 0
-    if (s->avctx->profile == 0 && s->avctx->level == 8) {
-        s->avctx->level = 0;
+    if (*profile == 0 && *level == 8) {
+        *level = 0;
     }
 
     return 0;
@@ -3211,13 +3211,19 @@
         } else if (startcode == GOP_STARTCODE) {
             mpeg4_decode_gop_header(s, gb);
         } else if (startcode == VOS_STARTCODE) {
-            mpeg4_decode_profile_level(s, gb);
-            if (s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO &&
-                (s->avctx->level > 0 && s->avctx->level < 9)) {
+            int profile, level;
+            mpeg4_decode_profile_level(s, gb, &profile, &level);
+            if (profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO &&
+                (level > 0 && level < 9)) {
                 s->studio_profile = 1;
                 next_start_code_studio(gb);
                 extension_and_user_data(s, gb, 0);
-            }
+            } else if (s->studio_profile) {
+                avpriv_request_sample(s->avctx, "Mixes studio and non studio profile\n");
+                return AVERROR_PATCHWELCOME;
+            }
+            s->avctx->profile = profile;
+            s->avctx->level   = level;
         } else if (startcode == VISUAL_OBJ_STARTCODE) {
             if (s->studio_profile) {
                 if ((ret = decode_studiovisualobject(ctx, gb)) < 0)
@@ -3238,6 +3244,7 @@
     s->avctx->has_b_frames = !s->low_delay;
 
     if (s->studio_profile) {
+        av_assert0(s->avctx->profile == FF_PROFILE_MPEG4_SIMPLE_STUDIO);
         if (!s->avctx->bits_per_raw_sample) {
             av_log(s->avctx, AV_LOG_ERROR, "Missing VOL header\n");
             return AVERROR_INVALIDDATA;
```
