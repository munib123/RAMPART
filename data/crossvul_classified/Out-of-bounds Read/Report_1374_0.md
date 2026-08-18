# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 1374_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1374_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1508-1548 of the vulnerable file.

				if ((o_es->stream_type == es->stream_type)
				        && ((o_es->flags & GF_M2TS_ES_STATIC_FLAGS_MASK) == (es->flags & GF_M2TS_ES_STATIC_FLAGS_MASK))
				        && (o_es->mpeg4_es_id == es->mpeg4_es_id)
				        && ((o_es->flags & GF_M2TS_ES_IS_SECTION) || ((GF_M2TS_PES *)o_es)->lang == ((GF_M2TS_PES *)es)->lang)
				   ) {
					gf_free(es);
					es = NULL;
				} else {
					gf_m2ts_es_del(o_es, ts);
					ts->ess[es->pid] = NULL;
				}
			}
		}

		if (es) {
			ts->ess[es->pid] = es;
			gf_list_add(pmt->program->streams, es);
			if (!(es->flags & GF_M2TS_ES_IS_SECTION) ) gf_m2ts_set_pes_framing(pes, GF_M2TS_PES_FRAMING_SKIP);

			nb_es++;
		}

		if (es->stream_type == GF_M2TS_VIDEO_HEVC) nb_hevc++;
		else if (es->stream_type == GF_M2TS_VIDEO_HEVC_TEMPORAL) nb_hevc_temp++;
		else if (es->stream_type == GF_M2TS_VIDEO_SHVC) nb_shvc++;
		else if (es->stream_type == GF_M2TS_VIDEO_SHVC_TEMPORAL) nb_shvc_temp++;
		else if (es->stream_type == GF_M2TS_VIDEO_MHVC) nb_mhvc++;
		else if (es->stream_type == GF_M2TS_VIDEO_MHVC_TEMPORAL) nb_mhvc_temp++;
	}

	//Table 2-139, implied hierarchy indexes
	if (nb_hevc_temp + nb_shvc + nb_shvc_temp + nb_mhvc+ nb_mhvc_temp) {
		for (i=0; i<gf_list_count(pmt->program->streams); i++) {
			GF_M2TS_PES *es = (GF_M2TS_PES *)gf_list_get(pmt->program->streams, i);
			if ( !(es->flags & GF_M2TS_ES_IS_PES)) continue;
			if (es->depends_on_pid) continue;

			switch (es->stream_type) {
			case GF_M2TS_VIDEO_HEVC_TEMPORAL:
				es->depends_on_pid = 1;
				break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1525,14 +1525,14 @@
 			if (!(es->flags & GF_M2TS_ES_IS_SECTION) ) gf_m2ts_set_pes_framing(pes, GF_M2TS_PES_FRAMING_SKIP);
 
 			nb_es++;
-		}
-
-		if (es->stream_type == GF_M2TS_VIDEO_HEVC) nb_hevc++;
-		else if (es->stream_type == GF_M2TS_VIDEO_HEVC_TEMPORAL) nb_hevc_temp++;
-		else if (es->stream_type == GF_M2TS_VIDEO_SHVC) nb_shvc++;
-		else if (es->stream_type == GF_M2TS_VIDEO_SHVC_TEMPORAL) nb_shvc_temp++;
-		else if (es->stream_type == GF_M2TS_VIDEO_MHVC) nb_mhvc++;
-		else if (es->stream_type == GF_M2TS_VIDEO_MHVC_TEMPORAL) nb_mhvc_temp++;
+
+			if (es->stream_type == GF_M2TS_VIDEO_HEVC) nb_hevc++;
+			else if (es->stream_type == GF_M2TS_VIDEO_HEVC_TEMPORAL) nb_hevc_temp++;
+			else if (es->stream_type == GF_M2TS_VIDEO_SHVC) nb_shvc++;
+			else if (es->stream_type == GF_M2TS_VIDEO_SHVC_TEMPORAL) nb_shvc_temp++;
+			else if (es->stream_type == GF_M2TS_VIDEO_MHVC) nb_mhvc++;
+			else if (es->stream_type == GF_M2TS_VIDEO_MHVC_TEMPORAL) nb_mhvc_temp++;
+		}
 	}
 
 	//Table 2-139, implied hierarchy indexes
```
