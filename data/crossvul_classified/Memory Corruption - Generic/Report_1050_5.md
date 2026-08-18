# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1050_5
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1050_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 103-143 of the vulnerable file.

enum mnemonic_focus { mf_normal, mf_tab, mf_mnemonic, mf_shortcut };

enum event_type { et_noevent = -1, et_char, et_charup, // is 1
		  et_mousemove, et_mousedown, et_mouseup,
		  et_crossing,	/* these four are assumed to be consecutive */
		  et_focus, // is 7
		  et_expose, et_visibility, et_resize, et_timer,
		  et_close/*request by user*/, et_create,
		  et_map, et_destroy/*window being freed*/,
		  et_selclear,
		  et_drag, et_dragout, et_drop,
		  et_lastnativeevent=et_drop,
		  et_controlevent, et_user };

enum visibility_state { vs_unobscured, vs_partially, vs_obscured };

enum et_subtype { et_buttonpress, et_buttonactivate, et_radiochanged,
		  et_listselected, et_listdoubleclick,
		  et_scrollbarchange,
		  et_textchanged, et_textfocuschanged,
		  et_lastsubtype };

enum sb { et_sb_top, et_sb_uppage, et_sb_up, et_sb_left=et_sb_up,
	  et_sb_down, et_sb_right=et_sb_down, et_sb_downpage,
	  et_sb_bottom,
	  et_sb_thumb, et_sb_thumbrelease };

struct sbevent {
    enum sb type;
    int32 pos;
};

typedef struct gevent {
    enum event_type type;
#define _GD_EVT_CHRLEN	10
    GWindow w;
    union {
	struct {
	    char *device;		/* for wacom devices */
	    uint32 time;
	    uint16 state;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -120,7 +120,7 @@
 		  et_listselected, et_listdoubleclick,
 		  et_scrollbarchange,
 		  et_textchanged, et_textfocuschanged,
-		  et_lastsubtype };
+		  et_save, et_lastsubtype };
 
 enum sb { et_sb_top, et_sb_uppage, et_sb_up, et_sb_left=et_sb_up,
 	  et_sb_down, et_sb_right=et_sb_down, et_sb_downpage,
```
