# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 1635_1
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1635_1`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 489-530 of the vulnerable file.

	  for (i = 0; i < 8; i++) { READ_BITS(j, 3); lzx->ALIGNED_len[i] = j; }
	  BUILD_TABLE(ALIGNED);
	  /* no break -- rest of aligned header is same as verbatim */
	case LZX_BLOCKTYPE_VERBATIM:
	  /* read lengths of and build main huffman decoding tree */
	  READ_LENGTHS(MAINTREE, 0, 256);
	  READ_LENGTHS(MAINTREE, 256, LZX_NUM_CHARS + lzx->num_offsets);
	  BUILD_TABLE(MAINTREE);
	  /* if the literal 0xE8 is anywhere in the block... */
	  if (lzx->MAINTREE_len[0xE8] != 0) lzx->intel_started = 1;
	  /* read lengths of and build lengths huffman decoding tree */
	  READ_LENGTHS(LENGTH, 0, LZX_NUM_SECONDARY_LENGTHS);
	  BUILD_TABLE_MAYBE_EMPTY(LENGTH);
	  break;

	case LZX_BLOCKTYPE_UNCOMPRESSED:
	  /* because we can't assume otherwise */
	  lzx->intel_started = 1;

	  /* read 1-16 (not 0-15) bits to align to bytes */
	  ENSURE_BITS(16);
	  if (bits_left > 16) i_ptr -= 2;
	  bits_left = 0; bit_buffer = 0;

	  /* read 12 bytes of stored R0 / R1 / R2 values */
	  for (rundest = &buf[0], i = 0; i < 12; i++) {
	    READ_IF_NEEDED;
	    *rundest++ = *i_ptr++;
	  }
	  R0 = buf[0] | (buf[1] << 8) | (buf[2]  << 16) | (buf[3]  << 24);
	  R1 = buf[4] | (buf[5] << 8) | (buf[6]  << 16) | (buf[7]  << 24);
	  R2 = buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24);
	  break;

	default:
	  D(("bad block type"))
	  return lzx->error = MSPACK_ERR_DECRUNCH;
	}
      }

      /* decode more of the block:
       * run = min(what's available, what's needed) */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -506,8 +506,7 @@
 	  lzx->intel_started = 1;
 
 	  /* read 1-16 (not 0-15) bits to align to bytes */
-	  ENSURE_BITS(16);
-	  if (bits_left > 16) i_ptr -= 2;
+	  if (bits_left == 0) ENSURE_BITS(16);
 	  bits_left = 0; bit_buffer = 0;
 
 	  /* read 12 bytes of stored R0 / R1 / R2 values */
```
