# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2588_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2588_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 174-203 of the vulnerable file.

 */
extern int _WM_midi_setup_noteoff(struct _mdi *mdi, uint8_t channel, uint8_t note, uint8_t velocity);
extern int _WM_midi_setup_endoftrack(struct _mdi *mdi);
extern int _WM_midi_setup_tempo(struct _mdi *mdi, uint32_t setting);

/* ===================== */

/*
 * Only non-standard midi event or non-track event setup functions need to be here
 */
extern int _WM_midi_setup_divisions(struct _mdi *mdi, uint32_t divisions);

/* ===================== */

/*
 * All other declarations
 */

extern struct _mdi * _WM_initMDI(void);
extern void _WM_freeMDI(struct _mdi *mdi);
extern uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t running_event);
extern void _WM_ResetToStart(struct _mdi *mdi);
extern void _WM_do_pan_adjust(struct _mdi *mdi, uint8_t ch);
extern void _WM_do_note_off_extra(struct _note *nte);
/* extern void _WM_DynamicVolumeAdjust(struct _mdi *mdi, int32_t *tmp_buffer, uint32_t buffer_used);*/
extern void _WM_AdjustChannelVolumes(struct _mdi *mdi, uint8_t ch);
extern float _WM_GetSamplesPerTick(uint32_t divisions, uint32_t tempo);

#endif /* __INTERNAL_MIDI_H */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -191,7 +191,7 @@
 
 extern struct _mdi * _WM_initMDI(void);
 extern void _WM_freeMDI(struct _mdi *mdi);
-extern uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint8_t running_event);
+extern uint32_t _WM_SetupMidiEvent(struct _mdi *mdi, uint8_t * event_data, uint32_t siz, uint8_t running_event);
 extern void _WM_ResetToStart(struct _mdi *mdi);
 extern void _WM_do_pan_adjust(struct _mdi *mdi, uint8_t ch);
 extern void _WM_do_note_off_extra(struct _note *nte);
```
