# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2588_4
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2588_4`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 44-84 of the vulnerable file.


/*
 Turns hmp file data into an event stream
 */
struct _mdi *
_WM_ParseNewMus(uint8_t *mus_data, uint32_t mus_size) {
    uint8_t mus_hdr[] = { 'M', 'U', 'S', 0x1A };
    uint32_t mus_song_ofs = 0;
    uint32_t mus_song_len = 0;
    uint16_t mus_ch_cnt1 = 0;
    uint16_t mus_ch_cnt2 = 0;
    uint16_t mus_no_instr = 0;
    uint32_t mus_data_ofs = 0;
    uint16_t * mus_mid_instr = NULL;
    uint16_t mus_instr_cnt = 0;
    struct _mdi *mus_mdi;
    uint32_t mus_divisions = 60;
    float tempo_f = 0.0;
    uint16_t mus_freq = 0;
    float samples_per_tick_f = 0.0;
    uint8_t mus_event[] = { 0, 0, 0, 0 };
    uint8_t mus_event_size = 0;
    uint8_t mus_prev_vol[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint32_t setup_ret = 0;
    uint32_t mus_ticks = 0;
    uint32_t sample_count = 0;
    float sample_count_f = 0.0;
    float sample_remainder = 0.0;
    uint16_t pitchbend_tmp = 0;

    if (mus_size < 17) {
        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_MUS, "File too short", 0);
        return NULL;
    }

    if (memcmp(mus_data, mus_hdr, 4)) {
        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_MUS, NULL, 0);
        return NULL;
    }

    // Get Song Length
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,8 @@
     float tempo_f = 0.0;
     uint16_t mus_freq = 0;
     float samples_per_tick_f = 0.0;
-    uint8_t mus_event[] = { 0, 0, 0, 0 };
+#define MUS_SZ 4
+    uint8_t mus_event[MUS_SZ] = { 0, 0, 0, 0 };
     uint8_t mus_event_size = 0;
     uint8_t mus_prev_vol[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
     uint32_t setup_ret = 0;
@@ -314,7 +315,7 @@
                 break;
         }
 
-        setup_ret = _WM_SetupMidiEvent(mus_mdi, (uint8_t *)mus_event, 0);
+        setup_ret = _WM_SetupMidiEvent(mus_mdi, (uint8_t *)mus_event, MUS_SZ, 0);
         if (setup_ret == 0) {
             goto _mus_end;
         }
```
