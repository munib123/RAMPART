# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5343_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5343_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 83-123 of the vulnerable file.

    ass_msg(lib, MSGL_INFO, "Shaper: FriBidi "
            FRIBIDI_VERSION " (SIMPLE)"
#ifdef CONFIG_HARFBUZZ
            " HarfBuzz-ng %s (COMPLEX)", hb_version_string()
#endif
           );
}

/**
 * \brief grow arrays, if needed
 * \param new_size requested size
 */
static bool check_allocations(ASS_Shaper *shaper, size_t new_size)
{
    if (new_size > shaper->n_glyphs) {
        if (!ASS_REALLOC_ARRAY(shaper->event_text, new_size) ||
            !ASS_REALLOC_ARRAY(shaper->ctypes, new_size) ||
            !ASS_REALLOC_ARRAY(shaper->emblevels, new_size) ||
            !ASS_REALLOC_ARRAY(shaper->cmap, new_size))
            return false;
    }
    return true;
}

/**
 * \brief Free shaper and related data
 */
void ass_shaper_free(ASS_Shaper *shaper)
{
#ifdef CONFIG_HARFBUZZ
    ass_cache_done(shaper->metrics_cache);
    free(shaper->features);
#endif
    free(shaper->event_text);
    free(shaper->ctypes);
    free(shaper->emblevels);
    free(shaper->cmap);
    free(shaper);
}

void ass_shaper_font_data_free(ASS_ShaperFontData *priv)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,6 +100,7 @@
             !ASS_REALLOC_ARRAY(shaper->emblevels, new_size) ||
             !ASS_REALLOC_ARRAY(shaper->cmap, new_size))
             return false;
+        shaper->n_glyphs = new_size;
     }
     return true;
 }
```
