# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 467_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `467_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2138-2178 of the vulnerable file.

            for (k = 0; k < source_package->tracks_count; k++) {
                if (!(temp_track = mxf_resolve_strong_ref(mxf, &source_package->tracks_refs[k], Track))) {
                    av_log(mxf->fc, AV_LOG_ERROR, "could not resolve source track strong ref\n");
                    ret = AVERROR_INVALIDDATA;
                    goto fail_and_free;
                }
                if (temp_track->track_id == component->source_track_id) {
                    source_track = temp_track;
                    break;
                }
            }
            if (!source_track) {
                av_log(mxf->fc, AV_LOG_ERROR, "material track %d: no corresponding source track found\n", material_track->track_id);
                break;
            }

            for (k = 0; k < mxf->essence_container_data_count; k++) {
                MXFEssenceContainerData *essence_data;

                if (!(essence_data = mxf_resolve_strong_ref(mxf, &mxf->essence_container_data_refs[k], EssenceContainerData))) {
                    av_log(mxf, AV_LOG_TRACE, "could not resolve essence container data strong ref\n");
                    continue;
                }
                if (!memcmp(component->source_package_ul, essence_data->package_ul, sizeof(UID)) && !memcmp(component->source_package_uid, essence_data->package_uid, sizeof(UID))) {
                    source_track->body_sid = essence_data->body_sid;
                    source_track->index_sid = essence_data->index_sid;
                    break;
                }
            }

            if(source_track && component)
                break;
        }
        if (!source_track || !component || !source_package) {
            if((ret = mxf_add_metadata_stream(mxf, material_track)))
                goto fail_and_free;
            continue;
        }

        if (!(source_track->sequence = mxf_resolve_strong_ref(mxf, &source_track->sequence_ref, Sequence))) {
            av_log(mxf->fc, AV_LOG_ERROR, "could not resolve source track sequence strong ref\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2155,7 +2155,7 @@
                 MXFEssenceContainerData *essence_data;
 
                 if (!(essence_data = mxf_resolve_strong_ref(mxf, &mxf->essence_container_data_refs[k], EssenceContainerData))) {
-                    av_log(mxf, AV_LOG_TRACE, "could not resolve essence container data strong ref\n");
+                    av_log(mxf->fc, AV_LOG_TRACE, "could not resolve essence container data strong ref\n");
                     continue;
                 }
                 if (!memcmp(component->source_package_ul, essence_data->package_ul, sizeof(UID)) && !memcmp(component->source_package_uid, essence_data->package_uid, sizeof(UID))) {
```
