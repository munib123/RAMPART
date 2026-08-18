# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1050_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1050_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 172-212 of the vulnerable file.


static void SD_DoCancel(struct sd_data *sd) {
    sd->done = true;
}

static int SD_Cancel(GGadget *g, GEvent *e) {
    if ( e->type==et_controlevent && e->u.control.subtype == et_buttonactivate ) {
	SD_DoCancel( GDrawGetUserData(GGadgetGetWindow(g)));
    }
return( true );
}

static int sd_e_h(GWindow gw, GEvent *event) {
    struct sd_data *sd = GDrawGetUserData(gw);

    if ( sd==NULL )
return( true );
    
    if ( event->type==et_close ) {
	SD_DoCancel( sd );
    } else if ( event->type==et_char ) {
	if ( event->u.chr.keysym == GK_F1 || event->u.chr.keysym == GK_Help ) {
	    help("scripting.html");
return( true );
	}
return( false );
    } else if ( event->type == et_map )	/* Above palettes */
	GDrawRaise(gw);
    else if ( event->type == et_resize )
	GDrawRequestExpose(gw,NULL,false);
return( true );
}

void ScriptDlg(FontView *fv,CharView *cv) {
    GRect pos;
    static GWindow gw;
    GWindowAttrs wattrs;
    GGadgetCreateData gcd[12], boxes[5], *barray[4][8], *hvarray[4][2];
#if !defined(_NO_FFSCRIPT) && !defined(_NO_PYTHON)
    GGadgetCreateData *rarray[4];
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -189,6 +189,10 @@
     
     if ( event->type==et_close ) {
 	SD_DoCancel( sd );
+    } else if ( event->type==et_controlevent && event->u.control.subtype==et_textchanged ) {
+    sd->fv->script_unsaved = !GTextFieldIsEmpty(GWidgetGetControl(sd->gw,CID_Script));
+    } else if ( event->type==et_controlevent && event->u.control.subtype==et_save ) {
+    sd->fv->script_unsaved = false;
     } else if ( event->type==et_char ) {
 	if ( event->u.chr.keysym == GK_F1 || event->u.chr.keysym == GK_Help ) {
 	    help("scripting.html");
```
