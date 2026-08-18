# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 1199_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1199_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 730-770 of the vulnerable file.

                      if (valid_isolate_count < 0)
                        break;
                    }
                  else if (FRIBIDI_IS_ISOLATE(RL_TYPE(fsi_pp)))
                    isolate_count++;
                  else if (isolate_count==0 && FRIBIDI_IS_LETTER (RL_TYPE (fsi_pp)))
                    {
                      fsi_base_level = FRIBIDI_DIR_TO_LEVEL (RL_TYPE (fsi_pp));
                      break;
                    }
                }

              /* Same behavior like RLI and LRI above */
              if (FRIBIDI_LEVEL_IS_RTL (fsi_base_level))
                new_level = level + 1 + (level%2);
              else
                new_level = level + 2 - (level%2);
            }

	  RL_LEVEL (pp) = level;
          RL_ISOLATE_LEVEL (pp) = isolate_level++;
          base_level_per_iso_level[isolate_level] = new_level;

	  if (!FRIBIDI_IS_NEUTRAL (override))
	    RL_TYPE (pp) = override;

          if (new_level <= FRIBIDI_BIDI_MAX_EXPLICIT_LEVEL)
            {
              valid_isolate_count++;
              PUSH_STATUS;
              level = new_level;
            }
          else
            isolate_overflow += 1;
        }
      else if (this_type == FRIBIDI_TYPE_BS)
	{
	  /* X8. All explicit directional embeddings and overrides are
	     completely terminated at the end of each paragraph. Paragraph
	     separators are not included in the embedding. */
	  break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -747,7 +747,9 @@
             }
 
 	  RL_LEVEL (pp) = level;
-          RL_ISOLATE_LEVEL (pp) = isolate_level++;
+          RL_ISOLATE_LEVEL (pp) = isolate_level;
+          if (isolate_level < FRIBIDI_BIDI_MAX_EXPLICIT_LEVEL-1)
+              isolate_level++;
           base_level_per_iso_level[isolate_level] = new_level;
 
 	  if (!FRIBIDI_IS_NEUTRAL (override))
```
