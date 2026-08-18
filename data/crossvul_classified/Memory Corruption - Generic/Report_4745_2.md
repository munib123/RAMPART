# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4745_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4745_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 168-205 of the vulnerable file.

			data += i + 1;
		    } else {
			i = data[0];
			if (x + i > state->xsize)
			    break; /* safety first */
			memset(out + x, data[1], i);
			data += 2;
		    }
		}
		if (x != state->xsize) {
		    /* didn't unpack whole line */
		    state->errcode = IMAGING_CODEC_OVERRUN;
		    return -1;
		}
	    }
	    break;
	case 16:
	    /* COPY chunk */
	    for (y = 0; y < state->ysize; y++) {
		UINT8* buf = (UINT8*) im->image[y];
		memcpy(buf+x, data, state->xsize);
		data += state->xsize;
	    }
	    break;
	case 18:
	    /* PSTAMP chunk */
	    break; /* ignored */
	default:
	    /* unknown chunk */
	    /* printf("unknown FLI/FLC chunk: %d\n", I16(ptr+4)); */
	    state->errcode = IMAGING_CODEC_UNKNOWN;
	    return -1;
	}
	ptr += I32(ptr);
    }

    return -1; /* end of frame */
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -185,7 +185,7 @@
 	    /* COPY chunk */
 	    for (y = 0; y < state->ysize; y++) {
 		UINT8* buf = (UINT8*) im->image[y];
-		memcpy(buf+x, data, state->xsize);
+		memcpy(buf, data, state->xsize);
 		data += state->xsize;
 	    }
 	    break;
```
