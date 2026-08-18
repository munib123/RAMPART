# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 292_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `292_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 236-268 of the vulnerable file.

      /* Regional indicators */
      if (_pango_Is_Regional_Indicator(ch) &&
	  _pango_Is_Regional_Indicator(peek_char)) {
	current_emoji_type = PANGO_EMOJI_TYPE_EMOJI_EMOJI;
      }

      /* Upgrade text presentation emoji to emoji presentation when followed by
       * ZWJ, Example U+1F441 U+200D U+1F5E8, eye + ZWJ + left speech bubble. */
      if ((ch == kEyeCharacter ||
	   ch == kWavingWhiteFlagCharacter) &&
	  peek_char == kZeroWidthJoinerCharacter) {
	current_emoji_type = PANGO_EMOJI_TYPE_EMOJI_EMOJI;
      }
    }

    if (iter->is_emoji == (gboolean) 2)
      iter->is_emoji = !PANGO_EMOJI_TYPE_IS_EMOJI (current_emoji_type);
    if (iter->is_emoji == PANGO_EMOJI_TYPE_IS_EMOJI (current_emoji_type))
    {
      iter->is_emoji = !PANGO_EMOJI_TYPE_IS_EMOJI (current_emoji_type);
      return TRUE;
    }
  }

  iter->is_emoji = PANGO_EMOJI_TYPE_IS_EMOJI (current_emoji_type);

  return TRUE;
}


/**********************************************************
 * End of code from Chromium
 **********************************************************/
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -253,6 +253,12 @@
     if (iter->is_emoji == PANGO_EMOJI_TYPE_IS_EMOJI (current_emoji_type))
     {
       iter->is_emoji = !PANGO_EMOJI_TYPE_IS_EMOJI (current_emoji_type);
+
+      /* Make sure we make progress.  Weird sequences, like a VC15 followed
+       * by VC16, can trick us into stalling otherwise. */
+      if (iter->start == iter->end)
+        iter->end = g_utf8_next_char (iter->end);
+
       return TRUE;
     }
   }
```
