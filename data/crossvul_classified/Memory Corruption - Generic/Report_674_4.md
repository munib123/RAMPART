# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 674_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `674_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 368-406 of the vulnerable file.

			val = _mm_and_si128(_mm_srli_si128(t, 1), mask);
			val = _mm_avg_epu16(val, _mm_and_si128(t, mask));
			val = _mm_packus_epi16(val, val);
			_mm_storeu_si128((__m128i*) co_dst, val);
			co_dst += 8;
			co_src0 += 16;
			co_src1 += 16;
			t = _mm_loadu_si128((__m128i*) cg_src0);
			t = _mm_avg_epu8(t, _mm_loadu_si128((__m128i*) cg_src1));
			val = _mm_and_si128(_mm_srli_si128(t, 1), mask);
			val = _mm_avg_epu16(val, _mm_and_si128(t, mask));
			val = _mm_packus_epi16(val, val);
			_mm_storeu_si128((__m128i*) cg_dst, val);
			cg_dst += 8;
			cg_src0 += 16;
			cg_src1 += 16;
		}
	}
}

static void nsc_encode_sse2(NSC_CONTEXT* context, const BYTE* data,
                            UINT32 scanline)
{
	nsc_encode_argb_to_aycocg_sse2(context, data, scanline);

	if (context->ChromaSubsamplingLevel > 0)
	{
		nsc_encode_subsampling_sse2(context);
	}
}

void nsc_init_sse2(NSC_CONTEXT* context)
{
	if (!IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE))
		return;

	PROFILER_RENAME(context->priv->prof_nsc_encode, "nsc_encode_sse2");
	context->encode = nsc_encode_sse2;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -385,7 +385,7 @@
 	}
 }
 
-static void nsc_encode_sse2(NSC_CONTEXT* context, const BYTE* data,
+static BOOL nsc_encode_sse2(NSC_CONTEXT* context, const BYTE* data,
                             UINT32 scanline)
 {
 	nsc_encode_argb_to_aycocg_sse2(context, data, scanline);
@@ -394,6 +394,8 @@
 	{
 		nsc_encode_subsampling_sse2(context);
 	}
+
+	return TRUE;
 }
 
 void nsc_init_sse2(NSC_CONTEXT* context)
```
