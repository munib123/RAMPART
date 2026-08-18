# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5733_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5733_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 591-631 of the vulnerable file.

    mtn2  = (int)((accumNm / 6.0f) + 0.5f);
    c1 = ((float)FFMAX(norm1,norm2)) / ((float)FFMAX(FFMIN(norm1,norm2),1));
    c2 = ((float)FFMAX(mtn1, mtn2))  / ((float)FFMAX(FFMIN(mtn1, mtn2), 1));
    mr = ((float)FFMAX(mtn1, mtn2))  / ((float)FFMAX(FFMAX(norm1,norm2),1));
    if (((mtn1 >=  500 || mtn2 >=  500) && (mtn1*2 < mtn2*1 || mtn2*2 < mtn1*1)) ||
        ((mtn1 >= 1000 || mtn2 >= 1000) && (mtn1*3 < mtn2*2 || mtn2*3 < mtn1*2)) ||
        ((mtn1 >= 2000 || mtn2 >= 2000) && (mtn1*5 < mtn2*4 || mtn2*5 < mtn1*4)) ||
        ((mtn1 >= 4000 || mtn2 >= 4000) && c2 > c1))
        ret = mtn1 > mtn2 ? match2 : match1;
    else if (mr > 0.005 && FFMAX(mtn1, mtn2) > 150 && (mtn1*2 < mtn2*1 || mtn2*2 < mtn1*1))
        ret = mtn1 > mtn2 ? match2 : match1;
    else
        ret = norm1 > norm2 ? match2 : match1;
    return ret;
}

static void copy_fields(const FieldMatchContext *fm, AVFrame *dst,
                        const AVFrame *src, int field)
{
    int plane;
    for (plane = 0; plane < 4 && src->data[plane]; plane++)
        av_image_copy_plane(dst->data[plane] + field*dst->linesize[plane], dst->linesize[plane] << 1,
                            src->data[plane] + field*src->linesize[plane], src->linesize[plane] << 1,
                            get_width(fm, src, plane), get_height(fm, src, plane) / 2);
}

static AVFrame *create_weave_frame(AVFilterContext *ctx, int match, int field,
                                   const AVFrame *prv, AVFrame *src, const AVFrame *nxt)
{
    AVFrame *dst;
    FieldMatchContext *fm = ctx->priv;

    if (match == mC) {
        dst = av_frame_clone(src);
    } else {
        AVFilterLink *outlink = ctx->outputs[0];

        dst = ff_get_video_buffer(outlink, outlink->w, outlink->h);
        if (!dst)
            return NULL;
        av_frame_copy_props(dst, src);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -608,7 +608,7 @@
                         const AVFrame *src, int field)
 {
     int plane;
-    for (plane = 0; plane < 4 && src->data[plane]; plane++)
+    for (plane = 0; plane < 4 && src->data[plane] && src->linesize[plane]; plane++)
         av_image_copy_plane(dst->data[plane] + field*dst->linesize[plane], dst->linesize[plane] << 1,
                             src->data[plane] + field*src->linesize[plane], src->linesize[plane] << 1,
                             get_width(fm, src, plane), get_height(fm, src, plane) / 2);
```
