# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 465_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `465_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 117-157 of the vulnerable file.


    if (streamid == PVA_VIDEO_PAYLOAD && pts_flag) {
        pva_pts = avio_rb32(pb);
        length -= 4;
    } else if (streamid == PVA_AUDIO_PAYLOAD) {
        /* PVA Audio Packets either start with a signaled PES packet or
         * are a continuation of the previous PES packet. New PES packets
         * always start at the beginning of a PVA Packet, never somewhere in
         * the middle. */
        if (!pvactx->continue_pes) {
            int pes_signal, pes_header_data_length, pes_packet_length,
                pes_flags;
            unsigned char pes_header_data[256];

            pes_signal             = avio_rb24(pb);
            avio_r8(pb);
            pes_packet_length      = avio_rb16(pb);
            pes_flags              = avio_rb16(pb);
            pes_header_data_length = avio_r8(pb);

            if (pes_signal != 1 || pes_header_data_length == 0) {
                pva_log(s, AV_LOG_WARNING, "expected non empty signaled PES packet, "
                                          "trying to recover\n");
                avio_skip(pb, length - 9);
                if (!read_packet)
                    return AVERROR(EIO);
                goto recover;
            }

            ret = avio_read(pb, pes_header_data, pes_header_data_length);
            if (ret != pes_header_data_length)
                return ret < 0 ? ret : AVERROR_INVALIDDATA;
            length -= 9 + pes_header_data_length;

            pes_packet_length -= 3 + pes_header_data_length;

            pvactx->continue_pes = pes_packet_length;

            if (pes_flags & 0x80 && (pes_header_data[0] & 0xf0) == 0x20) {
                if (pes_header_data_length < 5) {
                    pva_log(s, AV_LOG_ERROR, "header too short\n");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,6 +134,10 @@
             pes_flags              = avio_rb16(pb);
             pes_header_data_length = avio_r8(pb);
 
+            if (avio_feof(pb)) {
+                return AVERROR_EOF;
+            }
+
             if (pes_signal != 1 || pes_header_data_length == 0) {
                 pva_log(s, AV_LOG_WARNING, "expected non empty signaled PES packet, "
                                           "trying to recover\n");
```
