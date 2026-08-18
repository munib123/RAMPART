# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 190_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `190_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 865-905 of the vulnerable file.

    int length;
    put_bits(pbc, 1, 0);
    length = (-put_bits_count(pbc)) & 7;
    if (length)
        put_bits(pbc, length, (1 << length) - 1);
}

/* must be called before writing the header */
void ff_set_mpeg4_time(MpegEncContext *s)
{
    if (s->pict_type == AV_PICTURE_TYPE_B) {
        ff_mpeg4_init_direct_mv(s);
    } else {
        s->last_time_base = s->time_base;
        s->time_base      = FFUDIV(s->time, s->avctx->time_base.den);
    }
}

static void mpeg4_encode_gop_header(MpegEncContext *s)
{
    int hours, minutes, seconds;
    int64_t time;

    put_bits(&s->pb, 16, 0);
    put_bits(&s->pb, 16, GOP_STARTCODE);

    time = s->current_picture_ptr->f->pts;
    if (s->reordered_input_picture[1])
        time = FFMIN(time, s->reordered_input_picture[1]->f->pts);
    time = time * s->avctx->time_base.num;
    s->last_time_base = FFUDIV(time, s->avctx->time_base.den);

    seconds = FFUDIV(time, s->avctx->time_base.den);
    minutes = FFUDIV(seconds, 60); seconds = FFUMOD(seconds, 60);
    hours   = FFUDIV(minutes, 60); minutes = FFUMOD(minutes, 60);
    hours   = FFUMOD(hours  , 24);

    put_bits(&s->pb, 5, hours);
    put_bits(&s->pb, 6, minutes);
    put_bits(&s->pb, 1, 1);
    put_bits(&s->pb, 6, seconds);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -882,7 +882,7 @@
 
 static void mpeg4_encode_gop_header(MpegEncContext *s)
 {
-    int hours, minutes, seconds;
+    int64_t hours, minutes, seconds;
     int64_t time;
 
     put_bits(&s->pb, 16, 0);
```
