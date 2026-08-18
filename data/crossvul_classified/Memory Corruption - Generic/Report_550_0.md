# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 550_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `550_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 580-621 of the vulnerable file.

#ifdef OPJ_HAVE_LIBLCMS2
    /* Possible for: LCMS_VERSION >= 2000 :*/
    cmsCloseProfile(in_prof);
    cmsCloseProfile(out_prof);
#endif

    if (transform == NULL) {
#ifdef DEBUG_PROFILE
        fprintf(stderr, "%s:%d:color_apply_icc_profile\n\tcmsCreateTransform failed. "
                "ICC Profile ignored.\n", __FILE__, __LINE__);
#endif

#ifdef OPJ_HAVE_LIBLCMS1
        cmsCloseProfile(in_prof);
        cmsCloseProfile(out_prof);
#endif
        return;
    }

    if (image->numcomps > 2) { /* RGB, RGBA */
        if (prec <= 8) {
            unsigned char *inbuf, *outbuf, *in, *out;

            max = max_w * max_h;
            nr_samples = (size_t)(max * 3U * sizeof(unsigned char));
            in = inbuf = (unsigned char*)opj_image_data_alloc(nr_samples);
            out = outbuf = (unsigned char*)opj_image_data_alloc(nr_samples);

            if (inbuf == NULL || outbuf == NULL) {
                goto fails0;
            }

            r = image->comps[0].data;
            g = image->comps[1].data;
            b = image->comps[2].data;

            for (i = 0U; i < max; ++i) {
                *in++ = (unsigned char) * r++;
                *in++ = (unsigned char) * g++;
                *in++ = (unsigned char) * b++;
            }

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -597,82 +597,92 @@
     }
 
     if (image->numcomps > 2) { /* RGB, RGBA */
-        if (prec <= 8) {
-            unsigned char *inbuf, *outbuf, *in, *out;
-
-            max = max_w * max_h;
-            nr_samples = (size_t)(max * 3U * sizeof(unsigned char));
-            in = inbuf = (unsigned char*)opj_image_data_alloc(nr_samples);
-            out = outbuf = (unsigned char*)opj_image_data_alloc(nr_samples);
-
-            if (inbuf == NULL || outbuf == NULL) {
-                goto fails0;
-            }
-
-            r = image->comps[0].data;
-            g = image->comps[1].data;
-            b = image->comps[2].data;
-
-            for (i = 0U; i < max; ++i) {
-                *in++ = (unsigned char) * r++;
-                *in++ = (unsigned char) * g++;
-                *in++ = (unsigned char) * b++;
-            }
-
-            cmsDoTransform(transform, inbuf, outbuf, (cmsUInt32Number)max);
-
-            r = image->comps[0].data;
-            g = image->comps[1].data;
-            b = image->comps[2].data;
-
-            for (i = 0U; i < max; ++i) {
-                *r++ = (int) * out++;
-                *g++ = (int) * out++;
-                *b++ = (int) * out++;
-            }
-            ok = 1;
+        if ((image->comps[0].w == image->comps[1].w &&
+                image->comps[0].w == image->comps[2].w) &&
+                (image->comps[0].h == image->comps[1].h &&
+                 image->comps[0].h == image->comps[2].h)) {
+            if (prec <= 8) {
+                unsigned char *inbuf, *outbuf, *in, *out;
+
+                max = max_w * max_h;
+                nr_samples = (size_t)(max * 3U * sizeof(unsigned char));
+                in = inbuf = (unsigned char*)opj_image_data_alloc(nr_samples);
+                out = outbuf = (unsigned char*)opj_image_data_alloc(nr_samples);
+
+                if (inbuf == NULL || outbuf == NULL) {
+                    goto fails0;
+                }
+
+                r = image->comps[0].data;
+                g = image->comps[1].data;
+                b = image->comps[2].data;
+
+                for (i = 0U; i < max; ++i) {
+                    *in++ = (unsigned char) * r++;
+                    *in++ = (unsigned char) * g++;
+                    *in++ = (unsigned char) * b++;
+                }
+
+                cmsDoTransform(transform, inbuf, outbuf, (cmsUInt32Number)max);
+
+                r = image->comps[0].data;
+                g = image->comps[1].data;
+                b = image->comps[2].data;
+
+                for (i = 0U; i < max; ++i) {
+                    *r++ = (int) * out++;
+                    *g++ = (int) * out++;
+                    *b++ = (int) * out++;
+                }
+                ok = 1;
 
 fails0:
-            opj_image_data_free(inbuf);
-            opj_image_data_free(outbuf);
-        } else { /* prec > 8 */
-            unsigned short *inbuf, *outbuf, *in, *out;
-
-            max = max_w * max_h;
-            nr_samples = (size_t)(max * 3U * sizeof(unsigned short));
-            in = inbuf = (unsigned short*)opj_image_data_alloc(nr_samples);
-            out = outbuf = (unsigned short*)opj_image_data_alloc(nr_samples);
-
-            if (inbuf == NULL || outbuf == NULL) {
-                goto fails1;
-            }
-
-            r = image->comps[0].data;
-            g = image->comps[1].data;
-            b = image->comps[2].data;
-
-            for (i = 0U  ; i < max; ++i) {
-                *in++ = (unsigned short) * r++;
-                *in++ = (unsigned short) * g++;
-                *in++ = (unsigned short) * b++;
-            }
-
-            cmsDoTransform(transform, inbuf, outbuf, (cmsUInt32Number)max);
-
-            r = image->comps[0].data;
-            g = image->comps[1].data;
-            b = image->comps[2].data;
-
-            for (i = 0; i < max; ++i) {
-                *r++ = (int) * out++;
-                *g++ = (int) * out++;
-                *b++ = (int) * out++;
-            }
-            ok = 1;
+                opj_image_data_free(inbuf);
+                opj_image_data_free(outbuf);
+            } else { /* prec > 8 */
+                unsigned short *inbuf, *outbuf, *in, *out;
+
+                max = max_w * max_h;
+                nr_samples = (size_t)(max * 3U * sizeof(unsigned short));
+                in = inbuf = (unsigned short*)opj_image_data_alloc(nr_samples);
+                out = outbuf = (unsigned short*)opj_image_data_alloc(nr_samples);
+
+                if (inbuf == NULL || outbuf == NULL) {
+                    goto fails1;
+                }
+
+                r = image->comps[0].data;
+                g = image->comps[1].data;
+                b = image->comps[2].data;
+
+                for (i = 0U  ; i < max; ++i) {
+                    *in++ = (unsigned short) * r++;
+                    *in++ = (unsigned short) * g++;
+                    *in++ = (unsigned short) * b++;
+                }
+
+                cmsDoTransform(transform, inbuf, outbuf, (cmsUInt32Number)max);
+
+                r = image->comps[0].data;
+                g = image->comps[1].data;
+                b = image->comps[2].data;
+
+                for (i = 0; i < max; ++i) {
+                    *r++ = (int) * out++;
+                    *g++ = (int) * out++;
+                    *b++ = (int) * out++;
+                }
+                ok = 1;
 
 fails1:
-            opj_image_data_free(inbuf);
-            opj_image_data_free(outbuf);
+                opj_image_data_free(inbuf);
+                opj_image_data_free(outbuf);
+            }
+        } else {
+            fprintf(stderr,
+                    "[ERROR] Image components should have the same width and height\n");
+            cmsDeleteTransform(transform);
+            return;
         }
     } else { /* image->numcomps <= 2 : GRAY, GRAYA */
         if (prec <= 8) {
```
