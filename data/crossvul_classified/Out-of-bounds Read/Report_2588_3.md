# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2588_3
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2588_3`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "wm_error.h"
#include "f_midi.h"
#include "wildmidi_lib.h"
#include "internal_midi.h"
#include "reverb.h"
#include "sample.h"


struct _mdi *
_WM_ParseNewMidi(uint8_t *midi_data, uint32_t midi_size) {
    struct _mdi *mdi;

    uint32_t tmp_val;
    uint32_t midi_type;
    uint32_t track_size;
    uint8_t **tracks;
    uint32_t end_of_tracks = 0;
    uint32_t no_tracks;
    uint32_t i;
    uint32_t divisions = 96;
    uint32_t tempo = 500000;
    float samples_per_delta_f = 0.0;

    uint32_t sample_count = 0;
    float sample_count_f = 0.0;
    float sample_remainder = 0.0;
    uint8_t *sysex_store = NULL;
//  uint32_t sysex_store_len = 0;

    uint32_t *track_delta;
    uint8_t *track_end;
    uint32_t smallest_delta = 0;
    uint32_t subtract_delta = 0;
//  uint32_t tmp_length = 0;
//  uint8_t current_event = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,8 +43,8 @@
 
     uint32_t tmp_val;
     uint32_t midi_type;
-    uint32_t track_size;
     uint8_t **tracks;
+    uint32_t *track_size;
     uint32_t end_of_tracks = 0;
     uint32_t no_tracks;
     uint32_t i;
@@ -56,15 +56,11 @@
     float sample_count_f = 0.0;
     float sample_remainder = 0.0;
     uint8_t *sysex_store = NULL;
-//  uint32_t sysex_store_len = 0;
 
     uint32_t *track_delta;
     uint8_t *track_end;
     uint32_t smallest_delta = 0;
     uint32_t subtract_delta = 0;
-//  uint32_t tmp_length = 0;
-//  uint8_t current_event = 0;
-//  uint8_t current_event_ch = 0;
     uint8_t *running_event;
     uint32_t setup_ret = 0;
 
@@ -151,6 +147,7 @@
     _WM_midi_setup_divisions(mdi,divisions);
 
     tracks = malloc(sizeof(uint8_t *) * no_tracks);
+    track_size = malloc(sizeof(uint32_t) * no_tracks);
     track_delta = malloc(sizeof(uint32_t) * no_tracks);
     track_end = malloc(sizeof(uint8_t) * no_tracks);
     running_event = malloc(sizeof(uint8_t) * no_tracks);
@@ -168,28 +165,30 @@
         midi_data += 4;
         midi_size -= 4;
 
-        track_size = *midi_data++ << 24;
-        track_size |= *midi_data++ << 16;
-        track_size |= *midi_data++ << 8;
-        track_size |= *midi_data++;
+        /* track size */
+        tmp_val = *midi_data++ << 24;
+        tmp_val |= *midi_data++ << 16;
+        tmp_val |= *midi_data++ << 8;
+        tmp_val |= *midi_data++;
         midi_size -= 4;
-        if (midi_size < track_size) {
+        if (midi_size < tmp_val) {
             _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
             goto _end;
         }
-        if (track_size < 3) {
+        if (tmp_val < 3) {
             _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(bad track size)", 0);
             goto _end;
         }
-        if ((midi_data[track_size - 3] != 0xFF)
-                || (midi_data[track_size - 2] != 0x2F)
-                || (midi_data[track_size - 1] != 0x00)) {
+        if ((midi_data[tmp_val - 3] != 0xFF)
+                || (midi_data[tmp_val - 2] != 0x2F)
+                || (midi_data[tmp_val - 1] != 0x00)) {
             _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(missing EOT)", 0);
             goto _end;
         }
         tracks[i] = midi_data;
-        midi_data += track_size;
-        midi_size -= track_size;
+        track_size[i] = tmp_val;
+        midi_data += tmp_val;
+        midi_size -= tmp_val;
         track_end[i] = 0;
         running_event[i] = 0;
         track_delta[i] = 0;
@@ -197,9 +196,11 @@
         while (*tracks[i] > 0x7F) {
             track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
             tracks[i]++;
+            track_size[i]--;
         }
         track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
         tracks[i]++;
+        track_size[i]--;
 
         if (midi_type == 1 ) {
             if (track_delta[i] < smallest_delta) {
@@ -243,7 +244,7 @@
                     }
                 }
                 do {
-                    setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], running_event[i]);
+                    setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], track_size[i], running_event[i]);
                     if (setup_ret == 0) {
                         goto _end;
                     }
@@ -259,6 +260,7 @@
                             end_of_tracks++;
                             track_end[i] = 1;
                             tracks[i] += 3;
+                            track_size[i] -= 3;
                             goto NEXT_TRACK;
                         } else if ((tracks[i][0] == 0xff) && (tracks[i][1] == 0x51) && (tracks[i][2] == 0x03)) {
                             /* Tempo */
@@ -270,15 +272,23 @@
                         }
                     }
                     tracks[i] += setup_ret;
+                    track_size[i] -= setup_ret;
 
                     if (*tracks[i] > 0x7f) {
                         do {
+                            if (!track_size[i]) break;
                             track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                             tracks[i]++;
+                            track_size[i]--;
                         } while (*tracks[i] > 0x7f);
+                    }
+                    if (!track_size[i]) {
+                        _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
+                        goto _end;
                     }
                     track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                     tracks[i]++;
+                    track_size[i]--;
                 } while (!track_delta[i]);
                 if ((!smallest_delta) || (smallest_delta > track_delta[i])) {
                     smallest_delta = track_delta[i];
@@ -304,7 +314,7 @@
         for (i = 0; i < no_tracks; i++) {
             running_event[i] = 0;
             do {
-                setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], running_event[i]);
+                setup_ret = _WM_SetupMidiEvent(mdi, tracks[i], track_size[i], running_event[i]);
                 if (setup_ret == 0) {
                     goto _end;
                 }
@@ -329,16 +339,24 @@
                     }
                 }
                 tracks[i] += setup_ret;
+                track_size[i] -= setup_ret;
 
                 track_delta[i] = 0;
                 if (*tracks[i] > 0x7f) {
                     do {
+                        if (!track_size[i]) break;
                         track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                         tracks[i]++;
+                        track_size[i]--;
                     } while (*tracks[i] > 0x7f);
+                }
+                if (!track_size[i]) {
+                    _WM_GLOBAL_ERROR(__FUNCTION__, __LINE__, WM_ERR_CORUPT, "(too short)", 0);
+                    goto _end;
                 }
                 track_delta[i] = (track_delta[i] << 7) + (*tracks[i] & 0x7F);
                 tracks[i]++;
+                track_size[i]--;
 
                 sample_count_f = (((float) track_delta[i] * samples_per_delta_f)
                                   + sample_remainder);
@@ -372,6 +390,7 @@
     free(track_delta);
     free(running_event);
     free(tracks);
+    free(track_size);
     if (mdi->reverb) return (mdi);
     _WM_freeMDI(mdi);
     return (NULL);
```
