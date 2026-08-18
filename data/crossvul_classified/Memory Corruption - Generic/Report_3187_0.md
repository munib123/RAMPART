# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3187_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3187_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 749-789 of the vulnerable file.

		/* if match goes over the window edge, do two copy runs */
		i -= j; while (j-- > 0) *rundest++ = *runsrc++;
		runsrc = window;
	      }
	      while (i-- > 0) *rundest++ = *runsrc++;
	    }
	    else {
	      runsrc = rundest - match_offset;
	      while (i-- > 0) *rundest++ = *runsrc++;
	    }

	    this_run    -= match_length;
	    window_posn += match_length;
	  }
	} /* while (this_run > 0) */
	break;

      case LZX_BLOCKTYPE_UNCOMPRESSED:
	/* as this_run is limited not to wrap a frame, this also means it
	 * won't wrap the window (as the window is a multiple of 32k) */
	rundest = &window[window_posn];
	window_posn += this_run;
	while (this_run > 0) {
	  if ((i = i_end - i_ptr) == 0) {
	    READ_IF_NEEDED;
	  }
	  else {
	    if (i > this_run) i = this_run;
	    lzx->sys->copy(i_ptr, rundest, (size_t) i);
	    rundest  += i;
	    i_ptr    += i;
	    this_run -= i;
	  }
	}
	break;

      default:
	return lzx->error = MSPACK_ERR_DECRUNCH; /* might as well */
      }

      /* did the final match overrun our desired this_run length? */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -766,8 +766,13 @@
       case LZX_BLOCKTYPE_UNCOMPRESSED:
 	/* as this_run is limited not to wrap a frame, this also means it
 	 * won't wrap the window (as the window is a multiple of 32k) */
+        if (window_posn + this_run > lzx->window_size) {
+                D(("match ran over window boundary"))
+                return lzx->error = MSPACK_ERR_DECRUNCH;
+        }
 	rundest = &window[window_posn];
 	window_posn += this_run;
+
 	while (this_run > 0) {
 	  if ((i = i_end - i_ptr) == 0) {
 	    READ_IF_NEEDED;
@@ -888,8 +893,10 @@
   struct mspack_system *sys;
   if (lzx) {
     sys = lzx->sys;
-    sys->free(lzx->inbuf);
-    sys->free(lzx->window);
+    if(lzx->inbuf)
+        sys->free(lzx->inbuf);
+    if(lzx->window)
+        sys->free(lzx->window);
     sys->free(lzx);
   }
 }
```
