# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2588_1
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2588_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 25-65 of the vulnerable file.


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "wm_error.h"
#include "wildmidi_lib.h"
#include "internal_midi.h"
#include "reverb.h"
#include "f_hmi.h"

/*
 Turns hmp file data into an event stream
 */
struct _mdi *
_WM_ParseNewHmi(uint8_t *hmi_data, uint32_t hmi_size) {
    uint32_t hmi_tmp = 0;
    uint8_t *hmi_base = hmi_data;
    uint16_t hmi_bpm = 0;
    uint16_t hmi_division = 0;

//  uint32_t hmi_duration_secs = 0;
    uint32_t hmi_track_cnt = 0;
    uint32_t *hmi_track_offset = NULL;
    uint32_t i = 0;
    uint32_t j = 0;
    uint8_t *hmi_addr = NULL;
    uint32_t *hmi_track_header_length = NULL;
    struct _mdi *hmi_mdi = NULL;
    uint32_t tempo_f = 5000000.0;
    uint32_t *hmi_track_end = NULL;
    uint8_t hmi_tracks_ended = 0;
    uint8_t *hmi_running_event = NULL;
    uint32_t setup_ret = 0;
    uint32_t *hmi_delta = NULL;

    uint32_t smallest_delta = 0;
    uint32_t subtract_delta = 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -42,10 +42,10 @@
 _WM_ParseNewHmi(uint8_t *hmi_data, uint32_t hmi_size) {
     uint32_t hmi_tmp = 0;
     uint8_t *hmi_base = hmi_data;
+    uint32_t data_siz;
     uint16_t hmi_bpm = 0;
     uint16_t hmi_division = 0;
 
-//  uint32_t hmi_duration_secs = 0;
     uint32_t hmi_track_cnt = 0;
     uint32_t *hmi_track_offset = NULL;
     uint32_t i = 0;
@@ -74,8 +74,6 @@
         uint8_t channel;
     } *note;
 
-    //FIXME: This needs to be used for sanity check.
-    UNUSED(hmi_size);
 
     if (memcmp(hmi_data, "HMI-MIDISONG061595", 18)) {
         _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, NULL, 0);
@@ -216,6 +214,11 @@
             do {
                 hmi_data = hmi_base + hmi_track_offset[i];
                 hmi_delta[i] = 0;
+                if (hmi_track_offset[i] >= hmi_size) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                    goto _hmi_end;
+                }
+                data_siz = hmi_size - hmi_track_offset[i];
 
                 if (hmi_data[0] == 0xfe) {
                     // HMI only event of some sort.
@@ -223,14 +226,23 @@
                         hmi_tmp = (hmi_data[4] + 5);
                         hmi_data += hmi_tmp;
                         hmi_track_offset[i] += hmi_tmp;
+                        hmi_tmp += 4;
                     } else if (hmi_data[1] == 0x15) {
                         hmi_data += 4;
                         hmi_track_offset[i] += 4;
+                        hmi_tmp = 8;
+                    } else {
+                        hmi_tmp = 4;
                     }
                     hmi_data += 4;
                     hmi_track_offset[i] += 4;
+                    if (hmi_tmp > data_siz) {
+                        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                        goto _hmi_end;
+                    }
+                    data_siz -= hmi_tmp;
                 } else {
-                    if ((setup_ret = _WM_SetupMidiEvent(hmi_mdi,hmi_data,hmi_running_event[i])) == 0) {
+                    if ((setup_ret = _WM_SetupMidiEvent(hmi_mdi,hmi_data,data_siz,hmi_running_event[i])) == 0) {
                         goto _hmi_end;
                     }
                     if ((hmi_data[0] == 0xff) && (hmi_data[1] == 0x2f) && (hmi_data[2] == 0x00)) {
@@ -269,17 +281,25 @@
 
                         hmi_data += setup_ret;
                         hmi_track_offset[i] += setup_ret;
+                        data_siz -= setup_ret;
 
                         note[hmi_tmp].length = 0;
-                        if (*hmi_data > 0x7f) {
+                        if (data_siz && *hmi_data > 0x7f) {
                             do {
+                                if (!data_siz) break;
                                 note[hmi_tmp].length = (note[hmi_tmp].length << 7) | (*hmi_data & 0x7F);
                                 hmi_data++;
+                                data_siz--;
                                 hmi_track_offset[i]++;
                             } while (*hmi_data > 0x7F);
                         }
+                        if (!data_siz) {
+                            _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                            goto _hmi_end;
+                        }
                         note[hmi_tmp].length = (note[hmi_tmp].length << 7) | (*hmi_data & 0x7F);
                         hmi_data++;
+                        data_siz--;
                         hmi_track_offset[i]++;
 
                         if (note[hmi_tmp].length) {
@@ -293,20 +313,28 @@
                     } else {
                         hmi_data += setup_ret;
                         hmi_track_offset[i] += setup_ret;
+                        data_siz -= setup_ret;
                     }
                 }
 
                 // get track delta
                 // hmi_delta[i] = 0; // set at start of loop
-                if (*hmi_data > 0x7f) {
+                if (data_siz && *hmi_data > 0x7f) {
                     do {
+                        if (!data_siz) break;
                         hmi_delta[i] = (hmi_delta[i] << 7) | (*hmi_data & 0x7F);
                         hmi_data++;
+                        data_siz--;
                         hmi_track_offset[i]++;
                     } while (*hmi_data > 0x7F);
                 }
+                if (!data_siz) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_NOT_HMI, "file too short", 0);
+                    goto _hmi_end;
+                }
                 hmi_delta[i] = (hmi_delta[i] << 7) | (*hmi_data & 0x7F);
                 hmi_data++;
+                data_siz--;
                 hmi_track_offset[i]++;
             } while (!hmi_delta[i]);
             if ((!smallest_delta) || (smallest_delta > hmi_delta[i])) {
```
