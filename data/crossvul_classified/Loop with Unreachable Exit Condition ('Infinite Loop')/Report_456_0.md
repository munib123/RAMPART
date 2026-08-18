# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 456_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `456_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 177-217 of the vulnerable file.

// used with > 2^32 samples or non-Microsoft channels. The older stream version only differs in that it
// does not support the "mono optimization" feature where stereo blocks containing identical audio data
// in both channels are encoded in mono for better efficiency.

int WavpackSetConfiguration (WavpackContext *wpc, WavpackConfig *config, uint32_t total_samples)
{
    config->flags |= CONFIG_COMPATIBLE_WRITE;       // write earlier version streams

    if (total_samples == (uint32_t) -1)
        return WavpackSetConfiguration64 (wpc, config, -1, NULL);
    else
        return WavpackSetConfiguration64 (wpc, config, total_samples, NULL);
}

int WavpackSetConfiguration64 (WavpackContext *wpc, WavpackConfig *config, int64_t total_samples, const unsigned char *chan_ids)
{
    uint32_t flags, bps = 0;
    uint32_t chan_mask = config->channel_mask;
    int num_chans = config->num_channels;
    int i;

    wpc->stream_version = (config->flags & CONFIG_COMPATIBLE_WRITE) ? CUR_STREAM_VERS : MAX_STREAM_VERS;

    if ((config->qmode & QMODE_DSD_AUDIO) && config->bytes_per_sample == 1 && config->bits_per_sample == 8) {
#ifdef ENABLE_DSD
        wpc->dsd_multiplier = 1;
        flags = DSD_FLAG;

        for (i = 14; i >= 0; --i)
            if (config->sample_rate % sample_rates [i] == 0) {
                int divisor = config->sample_rate / sample_rates [i];

                if (divisor && (divisor & (divisor - 1)) == 0) {
                    config->sample_rate /= divisor;
                    wpc->dsd_multiplier = divisor;
                    break;
                }
            }

        // most options that don't apply to DSD we can simply ignore for now, but NOT hybrid mode!
        if (config->flags & CONFIG_HYBRID_FLAG) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -195,6 +195,11 @@
     int num_chans = config->num_channels;
     int i;
 
+    if (!config->sample_rate) {
+        strcpy (wpc->error_message, "sample rate cannot be zero!");
+        return FALSE;
+    }
+
     wpc->stream_version = (config->flags & CONFIG_COMPATIBLE_WRITE) ? CUR_STREAM_VERS : MAX_STREAM_VERS;
 
     if ((config->qmode & QMODE_DSD_AUDIO) && config->bytes_per_sample == 1 && config->bits_per_sample == 8) {
```
