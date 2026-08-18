# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4856_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4856_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1216-1256 of the vulnerable file.

		    if ((tmsize_t)sp->stream.avail_out != tif->tif_rawdatasize) {
			    tif->tif_rawcc =
				tif->tif_rawdatasize - sp->stream.avail_out;
			    TIFFFlushData1(tif);
			    sp->stream.next_out = tif->tif_rawdata;
			    sp->stream.avail_out = (uInt) tif->tif_rawdatasize;  /* this is a safe typecast, as check is made already in PixarLogPreEncode */
		    }
		    break;
		default:
			TIFFErrorExt(tif->tif_clientdata, module, "ZLib error: %s",
			sp->stream.msg ? sp->stream.msg : "(null)");
		    return (0);
		}
	} while (state != Z_STREAM_END);
	return (1);
}

static void
PixarLogClose(TIFF* tif)
{
	TIFFDirectory *td = &tif->tif_dir;

	/* In a really sneaky (and really incorrect, and untruthful, and
	 * troublesome, and error-prone) maneuver that completely goes against
	 * the spirit of TIFF, and breaks TIFF, on close, we covertly
	 * modify both bitspersample and sampleformat in the directory to
	 * indicate 8-bit linear.  This way, the decode "just works" even for
	 * readers that don't know about PixarLog, or how to set
	 * the PIXARLOGDATFMT pseudo-tag.
	 */
	td->td_bitspersample = 8;
	td->td_sampleformat = SAMPLEFORMAT_UINT;
}

static void
PixarLogCleanup(TIFF* tif)
{
	PixarLogState* sp = (PixarLogState*) tif->tif_data;

	assert(sp != 0);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1233,8 +1233,10 @@
 static void
 PixarLogClose(TIFF* tif)
 {
+        PixarLogState* sp = (PixarLogState*) tif->tif_data;
 	TIFFDirectory *td = &tif->tif_dir;
 
+	assert(sp != 0);
 	/* In a really sneaky (and really incorrect, and untruthful, and
 	 * troublesome, and error-prone) maneuver that completely goes against
 	 * the spirit of TIFF, and breaks TIFF, on close, we covertly
@@ -1243,8 +1245,19 @@
 	 * readers that don't know about PixarLog, or how to set
 	 * the PIXARLOGDATFMT pseudo-tag.
 	 */
-	td->td_bitspersample = 8;
-	td->td_sampleformat = SAMPLEFORMAT_UINT;
+
+        if (sp->state&PLSTATE_INIT) {
+            /* We test the state to avoid an issue such as in
+             * http://bugzilla.maptools.org/show_bug.cgi?id=2604
+             * What appends in that case is that the bitspersample is 1 and
+             * a TransferFunction is set. The size of the TransferFunction
+             * depends on 1<<bitspersample. So if we increase it, an access
+             * out of the buffer will happen at directory flushing.
+             * Another option would be to clear those targs. 
+             */
+            td->td_bitspersample = 8;
+            td->td_sampleformat = SAMPLEFORMAT_UINT;
+        }
 }
 
 static void
```
