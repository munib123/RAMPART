# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in c
**Pair ID:** 724_0
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `724_0`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```c
Lines 1022-1062 of the vulnerable file.

     * matched (if any). This is done inside PacketAlertFinalize() */
    /* PR: installed "tag" keywords are handled after the threshold inspection */

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_ALERT);
    PacketAlertFinalize(de_ctx, det_ctx, p);
    if (p->alerts.cnt > 0) {
        StatsAddUI64(tv, det_ctx->counter_alerts, (uint64_t)p->alerts.cnt);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_ALERT);
}

static void DetectRunCleanup(DetectEngineThreadCtx *det_ctx,
        Packet *p, Flow * const pflow)
{
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_CLEANUP);
    /* cleanup pkt specific part of the patternmatcher */
    PacketPatternCleanup(det_ctx);

    if (pflow != NULL) {
        /* update inspected tracker for raw reassembly */
        if (p->proto == IPPROTO_TCP && pflow->protoctx != NULL) {
            StreamReassembleRawUpdateProgress(pflow->protoctx, p,
                    det_ctx->raw_stream_progress);

            DetectEngineCleanHCBDBuffers(det_ctx);
        }
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_CLEANUP);
    SCReturn;
}

void RuleMatchCandidateTxArrayInit(DetectEngineThreadCtx *det_ctx, uint32_t size)
{
    DEBUG_VALIDATE_BUG_ON(det_ctx->tx_candidates);
    det_ctx->tx_candidates = SCCalloc(size, sizeof(RuleMatchCandidateTx));
    if (det_ctx->tx_candidates == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "failed to allocate %"PRIu64" bytes",
                (uint64_t)(size * sizeof(RuleMatchCandidateTx)));
    }
    det_ctx->tx_candidates_size = size;
    SCLogDebug("array initialized to %u elements (%"PRIu64" bytes)",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1039,7 +1039,9 @@
 
     if (pflow != NULL) {
         /* update inspected tracker for raw reassembly */
-        if (p->proto == IPPROTO_TCP && pflow->protoctx != NULL) {
+        if (p->proto == IPPROTO_TCP && pflow->protoctx != NULL &&
+            (p->flags & PKT_STREAM_EST))
+        {
             StreamReassembleRawUpdateProgress(pflow->protoctx, p,
                     det_ctx->raw_stream_progress);
 
```
