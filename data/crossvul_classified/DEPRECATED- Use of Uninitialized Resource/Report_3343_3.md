# CrossVul Fix Pair: DEPRECATED: Use of Uninitialized Resource in cpp
**Pair ID:** 3343_3
**Vulnerability Class:** DEPRECATED- Use of Uninitialized Resource
**CWE:** CWE-1187
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3343_3`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Use of Uninitialized Resource - This entry has been deprecated because it was a duplicate of CWE-908.

## Vulnerable Code
```cpp
Lines 400-440 of the vulnerable file.

        for (int i = 0; i + 1 < mark; ++i) {
            thread_handoff_[i].luma_y_end = htole16(luma_splits_tmp[i]);
            if (thread_handoff_[i].luma_y_end % sfv_lcm) {
                custom_exit(ExitCode::THREADING_PARTIAL_MCU);
            }
        }
        for (int i = 1; i < mark; ++i) {
            thread_handoff_[i].luma_y_start = thread_handoff_[i - 1].luma_y_end;
        }
    }
    /* read entire chunk into memory */
    //initialize_thread_id(0, 0, framebuffer[0]);
    if (thread_handoff_.size()) {
        thread_handoff_.back().luma_y_end = colldata->block_height(0);
    }
    return thread_handoff_;
}
void VP8ComponentDecoder::flush() {
        mux_splicer.drain(mux_reader_);
}
CodingReturnValue VP8ComponentDecoder::decode_chunk(UncompressedComponents * const colldata)
{
    mux_splicer.init(spin_workers_);
    /* cmpc is a global variable with the component count */


    /* construct 4x4 VP8 blocks to hold 8x8 JPEG blocks */
    if ( thread_state_[0] == nullptr || thread_state_[0]->context_[0].isNil() ) {
        /* first call */
        BlockBasedImagePerChannel<false> framebuffer;
        framebuffer.memset(0);
        for (size_t i = 0; i < framebuffer.size() && int( i ) < colldata->get_num_components(); ++i) {
            framebuffer[i] = &colldata->full_component_write((BlockType)i);
        }
        Sirikata::Array1d<BlockBasedImagePerChannel<false>, MAX_NUM_THREADS> all_framebuffers;
        for (size_t i = 0; i < all_framebuffers.size(); ++i) {
            all_framebuffers[i] = framebuffer;
        }
        size_t num_threads_needed = initialize_decoder_state(colldata,
                                                             all_framebuffers).size();

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -417,6 +417,7 @@
 void VP8ComponentDecoder::flush() {
         mux_splicer.drain(mux_reader_);
 }
+namespace{void nop(){}}
 CodingReturnValue VP8ComponentDecoder::decode_chunk(UncompressedComponents * const colldata)
 {
     mux_splicer.init(spin_workers_);
@@ -455,14 +456,19 @@
     if (do_threading_) {
         for (unsigned int thread_id = 0; thread_id < NUM_THREADS; ++thread_id) {
             unsigned int cur_spin_worker = thread_id;
-            spin_workers_[cur_spin_worker].work
-                = std::bind(worker_thread,
-                            thread_state_[thread_id],
-                            thread_id,
-                            colldata,
-                            mux_splicer.thread_target,
-                            getWorker(cur_spin_worker),
-                            &send_to_actual_thread_state);
+            if (!thread_state_[thread_id]) {
+                spin_workers_[cur_spin_worker].work
+                    = &nop;
+            } else {
+                spin_workers_[cur_spin_worker].work
+                    = std::bind(worker_thread,
+                                thread_state_[thread_id],
+                                thread_id,
+                                colldata,
+                                mux_splicer.thread_target,
+                                getWorker(cur_spin_worker),
+                                &send_to_actual_thread_state);
+            }
             spin_workers_[cur_spin_worker].activate_work();
         }
         flush();
```
