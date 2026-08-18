# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2588_5
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2588_5`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 250-290 of the vulnerable file.

                                if (xmi_notelen[j] == 0) {
                                    xmi_ch = j / 128;
                                    xmi_note = j - (xmi_ch * 128);
                                    _WM_midi_setup_noteoff(xmi_mdi, xmi_ch, xmi_note, 0);
                                } else {
                                    // otherwise work out new lowest delta
                                    if ((xmi_lowestdelta == 0) || (xmi_lowestdelta > xmi_notelen[j])) {
                                        xmi_lowestdelta = xmi_notelen[j];
                                    }
                                }
                            }
                            xmi_delta -= xmi_tmpdata;
                        } while (xmi_delta);

                    } else {
                        if ((xmi_data[0] == 0xff) && (xmi_data[1] == 0x51) && (xmi_data[2] == 0x03)) {
                            // Ignore tempo events
                            setup_ret = 6;
                            goto _XMI_Next_Event;
                        }
                        if ((setup_ret = _WM_SetupMidiEvent(xmi_mdi,xmi_data,0)) == 0) {
                            goto _xmi_end;
                        }

                        if ((*xmi_data & 0xf0) == 0x90) {
                            // Note on has extra data stating note length
                            xmi_ch = *xmi_data & 0x0f;
                            xmi_note = xmi_data[1];
                            xmi_data += setup_ret;
                            xmi_size -= setup_ret;
                            xmi_evntlen -= setup_ret;
                            xmi_subformlen -= setup_ret;

                            xmi_tmpdata = 0;

                            if (*xmi_data > 0x7f) {
                                while (*xmi_data > 0x7f) {
                                    xmi_tmpdata = (xmi_tmpdata << 7) | (*xmi_data++ & 0x7f);
                                    xmi_size--;
                                    xmi_evntlen--;
                                    xmi_subformlen--;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -267,7 +267,7 @@
                             setup_ret = 6;
                             goto _XMI_Next_Event;
                         }
-                        if ((setup_ret = _WM_SetupMidiEvent(xmi_mdi,xmi_data,0)) == 0) {
+                        if ((setup_ret = _WM_SetupMidiEvent(xmi_mdi,xmi_data, xmi_size, 0)) == 0) {
                             goto _xmi_end;
                         }
 
```
