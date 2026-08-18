# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1050_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1050_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 459-499 of the vulnerable file.

    unsigned int showhmetrics: 4;
    unsigned int showvmetrics: 4;
    unsigned int drag_and_drop: 1;
    unsigned int has_dd_no_cursor: 1;
    unsigned int any_dd_events_sent: 1;
    unsigned int resize_expected: 1;
	/* Some window managers do not honour my resize requests (if window is*/
	/*  maximized for example), but we depend on the resize request to    */
	/*  fix up the window. We do get a configure notify, but the window   */
	/*  stays the same size, so kludge things */
    unsigned int glyphlabel: 2;
    unsigned int notactive:1;			/* When embedded in a dlg */
    int16 magnify;
    int16 user_requested_magnify;
    struct searchview *sv;
    SplineChar *sc_near_top;
    int sel_index;
    struct lookup_subtable *cur_subtable;
    struct qg_data *qg;
    GPid pid_webfontserver;
} FontView;

typedef struct findsel {
    GEvent *e;
    real fudge;		/* One pixel fudge factor */
    real xl,xh, yl, yh;	/* One pixel fudge factor */
    real c_xl,c_xh, c_yl, c_yh;		/* fudge rectangle for control points, larger than above if alt is depressed */
    unsigned int select_controls: 1;	/* notice control points */
    unsigned int seek_controls: 1;	/* notice control points before base points */
    unsigned int all_controls: 1;	/* notice control points even if the base points aren't selected (in truetype point numbering mode where all cps are visible) */
    unsigned int alwaysshowcontrolpoints:1; /* if the BCP are forced on, then we want the selection code paths
					     * to also know that so the user can drag the BCP of a non selected splinepoint */
    real scale;
    PressedOn *p;
} FindSel;

typedef struct searchview {
    struct cvcontainer base;
    FontView dummy_fv;
    SplineFont dummy_sf;
    LayerInfo layerinfo[2];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -476,6 +476,7 @@
     struct lookup_subtable *cur_subtable;
     struct qg_data *qg;
     GPid pid_webfontserver;
+    bool script_unsaved; // Whether or not there's an unsaved script in script dialog
 } FontView;
 
 typedef struct findsel {
```
