# CrossVul Fix Pair: DEPRECATED: Use of Uninitialized Resource in cpp
**Pair ID:** 3343_2
**Vulnerability Class:** DEPRECATED- Use of Uninitialized Resource
**CWE:** CWE-1187
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3343_2`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Use of Uninitialized Resource - This entry has been deprecated because it was a duplicate of CWE-908.

## Vulnerable Code
```cpp
Lines 258-298 of the vulnerable file.

            break;
#endif
        }
    }
}

CodingReturnValue LeptonCodec::ThreadState::vp8_decode_thread(unsigned int thread_id,
                                                              UncompressedComponents *const colldata) {
    Sirikata::Array1d<uint32_t, (uint32_t)ColorChannel::NumBlockTypes> component_size_in_blocks;
    BlockBasedImagePerChannel<false> image_data;
    for (int i = 0; i < colldata->get_num_components(); ++i) {
        component_size_in_blocks[i] = colldata->component_size_in_blocks(i);
        image_data[i] = &colldata->full_component_write((BlockType)i);
    }
    Sirikata::Array1d<uint32_t,
                      (size_t)ColorChannel::NumBlockTypes> max_coded_heights
        = colldata->get_max_coded_heights();
    /* deserialize each block in planar order */

    dev_assert(luma_splits_.size() == 2); // not ready to do multiple work items on a thread yet
    int min_y = luma_splits_[0];
    int max_y = luma_splits_[1];
    while(true) {
        RowSpec cur_row = row_spec_from_index(decode_index_++, image_data, colldata->get_mcu_count_vertical(), max_coded_heights);
        if (cur_row.done) {
            break;
        }
        if (cur_row.luma_y >= max_y && thread_id + 1 != NUM_THREADS) {
            break;
        }
        if (cur_row.skip) {
            continue;
        }
        if (cur_row.luma_y < min_y) {
            continue;
        }
        decode_rowf(image_data,
                   component_size_in_blocks,
                   cur_row.component,
                   cur_row.curr_y);
        if (thread_id == 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -275,6 +275,7 @@
     /* deserialize each block in planar order */
 
     dev_assert(luma_splits_.size() == 2); // not ready to do multiple work items on a thread yet
+    always_assert(luma_splits_.size() >= 2);
     int min_y = luma_splits_[0];
     int max_y = luma_splits_[1];
     while(true) {
```
