# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1050_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1050_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 63-103 of the vulnerable file.

#include "tottfgpos.h"
#include "unicodelibinfo.h"
#include "ustring.h"
#include "utype.h"

#include <math.h>
#include <unistd.h>

#if defined (__MINGW32__)
#include <windows.h>
#endif

int OpenCharsInNewWindow = 0;
char *RecentFiles[RECENT_MAX] = { NULL };
int save_to_dir = 0;			/* use sfdir rather than sfd */
unichar_t *script_menu_names[SCRIPT_MENU_MAX];
char *script_filenames[SCRIPT_MENU_MAX];
extern int onlycopydisplayed, copymetadata, copyttfinstr, add_char_to_name_list;
int home_char='A';
int compact_font_on_open=0;
int navigation_mask = 0;		/* Initialized in startui.c */

static char *fv_fontnames = MONO_UI_FAMILIES;
extern void python_call_onClosingFunctions();

#define	FV_LAB_HEIGHT	15

#ifdef BIGICONS
#define fontview_width 32
#define fontview_height 32
static unsigned char fontview_bits[] = {
   0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x02, 0x20, 0x80, 0x00,
   0x82, 0x20, 0x86, 0x08, 0x42, 0x21, 0x8a, 0x14, 0xc2, 0x21, 0x86, 0x04,
   0x42, 0x21, 0x8a, 0x14, 0x42, 0x21, 0x86, 0x08, 0x02, 0x20, 0x80, 0x00,
   0xaa, 0xaa, 0xaa, 0xaa, 0x02, 0x20, 0x80, 0x00, 0x82, 0xa0, 0x8f, 0x18,
   0x82, 0x20, 0x91, 0x24, 0x42, 0x21, 0x91, 0x02, 0x42, 0x21, 0x91, 0x02,
   0x22, 0x21, 0x8f, 0x02, 0xe2, 0x23, 0x91, 0x02, 0x12, 0x22, 0x91, 0x02,
   0x3a, 0x27, 0x91, 0x24, 0x02, 0xa0, 0x8f, 0x18, 0x02, 0x20, 0x80, 0x00,
   0xfe, 0xff, 0xff, 0xff, 0x02, 0x20, 0x80, 0x00, 0x42, 0x20, 0x86, 0x18,
   0xa2, 0x20, 0x8a, 0x04, 0xa2, 0x20, 0x86, 0x08, 0xa2, 0x20, 0x8a, 0x10,
   0x42, 0x20, 0x8a, 0x0c, 0x82, 0x20, 0x80, 0x00, 0x02, 0x20, 0x80, 0x00,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,6 +80,7 @@
 extern int onlycopydisplayed, copymetadata, copyttfinstr, add_char_to_name_list;
 int home_char='A';
 int compact_font_on_open=0;
+bool warn_script_unsaved = true;
 int navigation_mask = 0;		/* Initialized in startui.c */
 
 static char *fv_fontnames = MONO_UI_FAMILIES;
@@ -534,6 +535,22 @@
 return( ret );
 }
 
+static int AskScriptChanged() {
+    int ret;
+    char *buts[4];
+
+    buts[0] = _("_Yes");
+    buts[1] = _("Yes, and don't _remind me again");
+    buts[2] = _("_No");
+    buts[3] = NULL;
+    ret = gwwv_ask( _("Unsaved script"),(const char **) buts,0,2,_("You have an unsaved script in the «Execute Script» dialog. Do you intend to discard it?"));
+    if (ret == 1) {
+        warn_script_unsaved = false;
+        SavePrefs(true);
+    }
+return( ret );
+}
+
 int _FVMenuGenerate(FontView *fv,int family) {
     FVFlattenAllBitmapSelections(fv);
 return( SFGenerateFont(fv->b.sf,fv->b.active_layer,family,fv->b.normal==NULL?fv->b.map:fv->b.normal) );
@@ -858,6 +875,9 @@
 
     if ( fv->b.nextsame!=NULL || fv->b.sf->fv!=&fv->b ) {
 	/* There's another view, can close this one with no problems */
+    } else if ( warn_script_unsaved && fv->script_unsaved && 
+                AskScriptChanged()==2 ) {
+        return false;
     } else if ( SFAnyChanged(sf) ) {
 	i = AskChanged(fv->b.sf);
 	if ( i==2 )	/* Cancel */
```
